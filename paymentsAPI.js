//const { Skyflow, generateBearerTokenFromCreds } = require('skyflow-node');
var forge = require('node-forge');
const axios = require('axios');
const crypto = require('crypto');

exports.paymentsAPI = async function (event) {
    let functionResponse = {
        bodyBytes: "",
        headers: {
            "Content-Type": "application/json",
            "Error-From-Client": "false",
        },
        statusCode: 200,
        transactionStatus: 'pending'
    };

    try {
        const buf = Buffer.from(event.data, 'base64')
        const data = JSON.parse(buf.toString())
        const response3DS = await flow3DS(data.request3DS, data.keyIntegration); //todo: mapping error
        const responseBulk=await flowBulk(data.requestBulk, data.keyIntegration);

        functionResponse.bodyBytes = JSON.stringify(responseBulk);
        functionResponse.transactionStatus = responseBulk.transactionStatus;
        return functionResponse

    } catch (err) {
        console.log("Err:", err)
        if (err.response) {
            functionResponse.bodyBytes = JSON.stringify(err.response.data);
            functionResponse.statusCode = err.response.status;
            functionResponse.headers["Error-From-Client"] = "true";
        } else {
            functionResponse.bodyBytes = `Internal error: ${JSON.stringify(err.message)}`;
            functionResponse.statusCode = 500;
        }
        return functionResponse
    }
};

const flow3DS = async(request3DS, keyIntegration) => {
    const aesEncryption = createAESEncryption(keyIntegration.seedAES);
    const plainText = obteinXmlRequest(request3DS);
    const request3dsEncryptedData = aesEncryption.encrypt(plainText);
    //console.log('Encrypted:', request3dsEncryptedData);
    console.log("plaintext:", plainText)
    try {
        const response3dsEncryptedData = await client3dsflow(request3dsEncryptedData, keyIntegration.data0);
        //console.log('dataresponse3ds:', response3dsEncryptedData);
        const response3dsDecryptedData = aesEncryption.decrypt(response3dsEncryptedData);
        console.log('Decrypted:', response3dsDecryptedData);
        return response3dsDecryptedData;
    } catch (error) {
        //console.error('Error in flow3DS:', error);
        throw error;
    }
};

const flowBulk = async(requestBulk, keyIntegration) => {
    //console.log('requestBulk:', requestBulk)
    const jsonString = JSON.stringify(requestBulk);
    const aesEncryption = createAESEncryption(keyIntegration.seedAES);
    const requestBulkEncryptedData = aesEncryption.encrypt(jsonString);
    try {
        const responseBulkEncryptedData = await clientBulkFlow(requestBulkEncryptedData, keyIntegration.data0);
        const responseBulkDecryptedData = JSON.parse(aesEncryption.decrypt(responseBulkEncryptedData));
        //console.log('Decrypted Response:', responseBulkDecryptedData);
        const transactionStatus = responseBulkDecryptedData && 'CdResponse' in responseBulkDecryptedData && responseBulkDecryptedData.CdResponse.trim() === '0C' ? 'success' : 'declined';

        return {
            data: responseBulkDecryptedData,
            transactionStatus: transactionStatus
        };

    } catch (error) {
        console.error('Error in flowBulk:', error);
        throw error;
    }
};

function obteinXmlRequest(request3DS) {
    const xml = `
        <?xml version="1.0" encoding="UTF-8" ?>
        <TRANSACTION3DS>
          <business>
            <bs_idCompany>${request3DS.TRANSACTION3DS.business.bs_idCompany}</bs_idCompany>
            <bs_idBranch>${request3DS.TRANSACTION3DS.business.bs_idBranch}</bs_idBranch>
            <bs_country>${request3DS.TRANSACTION3DS.business.bs_country}</bs_country>
            <bs_user>${request3DS.TRANSACTION3DS.business.bs_user}</bs_user>
            <bs_pwd>${request3DS.TRANSACTION3DS.business.bs_pwd}</bs_pwd>
          </business>
          <transaction>
            <tx_merchant>${request3DS.TRANSACTION3DS.transaction.tx_merchant}</tx_merchant>
            <tx_reference>${request3DS.TRANSACTION3DS.transaction.tx_reference}</tx_reference>
            <tx_amount>${request3DS.TRANSACTION3DS.transaction.tx_amount}</tx_amount>
            <tx_currency>${request3DS.TRANSACTION3DS.transaction.tx_currency}</tx_currency>
            <creditcard>
              <cc_name>${request3DS.TRANSACTION3DS.transaction.creditcard.cc_name}</cc_name>
              <cc_number>${request3DS.TRANSACTION3DS.transaction.creditcard.cc_number}</cc_number>
              <cc_expMonth>${request3DS.TRANSACTION3DS.transaction.creditcard.cc_expMonth}</cc_expMonth>
              <cc_expYear>${request3DS.TRANSACTION3DS.transaction.creditcard.cc_expYear}</cc_expYear>
              <cc_cvv>${request3DS.TRANSACTION3DS.transaction.creditcard.cc_cvv}</cc_cvv>
            </creditcard>
            <billing>
                <bl_billingPhone>${request3DS.TRANSACTION3DS.transaction.bl_billingPhone}</bl_billingPhone>
                <bl_billingEmail>${request3DS.TRANSACTION3DS.transaction.bl_billingEmail}</bl_billingEmail>
             </billing>
            <tx_urlResponse>${request3DS.TRANSACTION3DS.transaction.tx_urlResponse}</tx_urlResponse>
            <tx_cobro>${request3DS.TRANSACTION3DS.transaction.tx_cobro}</tx_cobro>
          </transaction>
        </TRANSACTION3DS>
    `;
    return xml;
}

const client3dsflow = async(encryptedData, data0) => {
    const url = 'https://qa3.mitec.com.mx/ws3dsecure/Auth3dsecure'; //todo: change to production URL
    const xmlData = `<pgs><data0>${data0}</data0><data>${encryptedData}</data></pgs>`;
    console.log('xmlData:', xmlData)
    try {
        const response = await axios({
            method: 'post',
            url: url,
            data: `xml=${encodeURIComponent(xmlData)}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        console.log('responsepiloso:', response.data)
        const regex = /<input[^>]*name="strResponse"[^>]*value="([^"]*)"/;
        const matches = regex.exec(response.data);

        if (matches && matches[1]) {
            const strResponseValue = matches[1];
            return strResponseValue;
        } else {
            throw new Error("Variable to next flow not found");
        }
    } catch (error) {
        throw error;
    }
}

const clientBulkFlow = async(encryptedData, data0) => {
    const url = 'https://qa3.mitec.com.mx/pgs/cobroXml';  //todo: change to production URL
    const requestData = JSON.stringify({
        "data0": data0,
        "data": encryptedData
    });

    try {
        const response = await axios({
            method: 'post',
            url: url,
            data: requestData,
            headers: {
                'Content-Type': 'application/json'
            }
        });

        return response.data;
    } catch (error) {
        throw error;
    }
}

function createAESEncryption(keyHex) {
    if (keyHex.length !== 32) {
        throw new Error('Invalid key length for AES-128. Key must be 32 hexadecimal characters (16 bytes).');
    }

    const key = Buffer.from(keyHex, 'hex');

    function encrypt(plaintext) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const encryptedText = Buffer.concat([iv, Buffer.from(encrypted, 'base64')]).toString('base64');
        return encryptedText;
    }

    function decrypt(encryptedData) {
        const encryptedBuffer = Buffer.from(encryptedData, 'base64');
        const iv = encryptedBuffer.slice(0, 16);
        const ciphertext = encryptedBuffer.slice(16);

        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    return { encrypt, decrypt };
}
