//const { Skyflow, generateBearerTokenFromCreds } = require('skyflow-node');
var forge = require('node-forge');
const axios = require('axios');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');

exports.paymentsAPI = async function (event) {
    var paymentResponse, error, authdata
    try {
        const buf = Buffer.from(event.data, 'base64')
        const data = JSON.parse(buf.toString())
        const {credentials, vaultURL, vaultID, modulus, publicExponent, purchaseEndpoint} = process.env;
        const {card_number, pin, cvv, expiry_month, expiry_year, interswitch_access_token} = data;
        //const response3DS = await flow3DS(data.request3DS, data.keyIntegration); //todo: mapping error
        const responseBulk=await flowBulk(data.requestBulk, data.keyIntegration);

        let statusCode = 200
        paymentResponse = data
        let res = {
            status: statusCode,
            paymentResponse: paymentResponse,
            error: null,
            errorFromClient: false
        }
        return res

    } catch (err) {
        console.log("Error processing payment:", err)
        error = err
        let statusCode = error?.response?.status ?? null
        if (error.response && error.response.data) {
            error = error.response.data
        }
        let res = {
            status: statusCode,
            paymentResponse: null,
            error: error,
            errorFromClient: true
        }
        console.log(JSON.stringify(res));
        return res
    }
};

async function flow3DS(request3DS, keyIntegration) {
    const aesEncryption = createAESEncryption(keyIntegration.seedAES);
    const plainText = obteinXmlRequest(request3DS);
    const request3dsEncryptedData = aesEncryption.encrypt(plainText);
    //console.log('Encrypted:', request3dsEncryptedData);
    //console.log("plaintext:", plainText)
    try {
        const response3dsEncryptedData = await client3dsflow(request3dsEncryptedData, keyIntegration.data0);
        //console.log('dataresponse3ds:', response3dsEncryptedData);
        const response3dsDecryptedData = aesEncryption.decrypt(response3dsEncryptedData);
        //console.log('Decrypted:', response3dsDecryptedData);
        return response3dsDecryptedData;
    } catch (error) {
        //console.error('Error in flow3DS:', error);
        throw error;
    }
};

async function flowBulk(requestBulk, keyIntegration) {
    console.log('requestBulk:', requestBulk)
    const jsonString = JSON.stringify(requestBulk);
    const aesEncryption = finalahorasi("B531B42EAC343095DF38259B2D08A431");
    const requestBulkEncryptedData = aesEncryption.encrypt(jsonString);
    console.log('Encrypted:', requestBulkEncryptedData);
    console.log("decrypted:-------", aesEncryption.decrypt(requestBulkEncryptedData), "------------")
    const testi="Xd0Nb9JMuEjyK5MRxFIk+GjfBHGQmBcLubb3JMdp/UtXgC6XHaPYoagVmcTReYhCx00weTxMUGr2Vn/mAP3IQr3iUFa6Fip9tBSTZyIyArQAMM5UBJ39Bk1U9IB82DLbBGivW6CYVdXSre4rX2e+LcmDYwA807X7/W8Xb4kAeoAsdeBFgHjemIM7PTT0V6jvrOEyMjpsFCtP963+u2BaomKGZBK27PmP6wI4umVNTuT5rMM+a9+qxyfIBPhZIBIJrvPUCgIc6hUNXIAHwnSpCFidW2529hVN5J3rV3PCcKhia7qqfLOtdOEaLQUPJXOrpEI8KeYSyUmpHmphxs/M+aRKy3tG5Dxeysv+jcVA1TMXBSgSJK3z4XzfTIKv6MOn0/qZZ8k2Jh/njTb3vs1alUxx/4z3bwDAP59t9pILhN/MiFP2KaZWc30ZUTyTwtoCoU9I3+C2hLeFlQ+N7ucwDc4n7cY/OsJgVUubinjisZO89SOrzWYHgoHWCQplpAWip+OAGhNc8xeMSfRZGu+5FIUSGHYohz8ezNrHAB0cz+uvmWO+bP6C969HM6gUyqJ2x1n/FsStUnE5be12n/6twMWiDUCHnCi7aFyUl6Uq+edHGs4S4NMQqymOgFWzki/kcKzWH8Ua8o4JL7kSQGnnyuoo/ljJEzivE8YFcllbhzI="
    console.log("decryptedsadasdasdadsasd:-------", aesEncryption.decrypt(testi), "------------")
    try {
        const responseBulkEncryptedData = await clientBulkFlow(requestBulkEncryptedData, keyIntegration.data0);
        console.log('dataresponse3ds:', responseBulkEncryptedData);
        const responseBulkDecryptedData = aesEncryption.decrypt(responseBulkEncryptedData);
        console.log('Decrypted Response:', responseBulkDecryptedData);

        /*console.log('Encoded Data:', responseBulkEncryptedData);
        const decodedData = Buffer.from(responseBulkEncryptedData, 'base64').toString('binary');
        console.log('Decoded Binary Data:', decodedData);
        const decryptedData = aesEncryption.decrypt(decodedData);
        console.log('Decrypted Data:', decryptedData);

*/

        return {};
    } catch (error) {
        //console.error('Error in flow3DS:', error);
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
            <tx_reference>${requestf3DS.TRANSACTION3DS.transaction.tx_reference}</tx_reference>
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

function createAESEncryption(keyHex) {
    if (keyHex.length !== 32) {
        throw new Error('Invalid key length for AES-128. Key must be 32 hexadecimal characters (16 bytes).');
    }
    const key = Buffer.from(keyHex, 'hex');

    function pkcs7Pad(buffer, block_size) {
        const padding = block_size - (buffer.length % block_size);
        const paddingBuffer = Buffer.alloc(padding, padding);
        return Buffer.concat([buffer, paddingBuffer]);
    }

    function pkcs7Unpad(buffer) {
        const padding = buffer[buffer.length - 1];
        return buffer.slice(0, -padding);
    }

    function encrypt(plaintext) {
        const iv = crypto.randomBytes(16); // AES block size
        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
        const plaintextBuffer = Buffer.from(plaintext, 'utf8');
        const paddedPlaintext = pkcs7Pad(plaintextBuffer, 16);
        const ciphertext = Buffer.concat([cipher.update(paddedPlaintext), cipher.final()]);
        return Buffer.concat([iv, ciphertext]).toString('base64');
    }

    function decrypt(encryptedData) {
        try {
            const encryptedBuffer = Buffer.from(encryptedData, 'base64');
            const iv = encryptedBuffer.slice(0, 16);
            const ciphertext = encryptedBuffer.slice(16);
            const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
            const decryptedText = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            const unpaddedText = pkcs7Unpad(decryptedText);
            return unpaddedText.toString('utf8');
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    }

    return { encrypt, decrypt };
}

async function client3dsflow(encryptedData, data0) {
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

async function clientBulkFlow(encryptedData, data0) {
    const url = 'https://qa3.mitec.com.mx/pgs/cobroXml';  //todo: change to production URL
    const requestData = JSON.stringify({
        "data0": data0,
        "data": encryptedData
    });
    const requestData2 =JSON.stringify({"data0":"9265660159","data":"hgEt8CVbZ6mLGkF6CMC/EsgM9iPfUNuFddDZXg2QWOiCJWp56AKXrbuTluppvaQJGlO9O/Ay6rGg78+iv00yzO+LcHdq6Y+3FUcd/3pFifiFdwcuVhhkgikBUETrP2xLv1owrEqWp+Yy8ZEt35xG08OdBgWwxiUYUs/nie/gi+DxvruQSFJ37L4JIMArpeBFR3f5aVP/lfqRaKM/QiuNkxycTqlhMVq0vGjPwvRIii9eBYdpMb0KLy9c658YWDwCdpMpWEejSWxN6fnjv9edMuivZnn0RiRUqG0cy0yHCapKUMYJ4IdbKzXBpafj+IJ9DQ4LX5GCSogHo2Z5MNEIw5u6DrY+R8AI+4NzBzpoYqfZtK69ESe8AF8pS434mtk1kWvxGo8YWGnbDfLPlUqQ2CY2HU/61hGemCj7nlXE3mJL02e+vO8Vh7J7+OEn5TNz1mKe7XNkSAh1ZtPDgGHCUkEdT0+gBeLMqzFb5IBNmk+93cNCFaAOC3sO7uwDH8783Ub86hHRVTJ4O8dbH27f7ao0dRQgZLlATWe11DuvXzmBkol+nQj4lPehWKaaUsIfnrh6ktCNxHuWxJCNzf2qFM+APDuchKupT8rz90YJNovDsLR67JT5lxZqZKYEhbTz5nre3hQAhDm02BueAqLQIolVZ0wxAMKrVSD+MSGlhEm8EXVR5rUoWqmYErIyVfyKVHSMUXkjfqtkDDvLApsbL//Hv3wrTRNOY0bJRjyA0KohekUnYvU+DCHI+qh2JYP8dozaHNg7vqrqUrAhVNDm0Q=="});

    try {
        const response = await axios({
            method: 'post',
            url: url,
            data: requestData,
            headers: {
                'Content-Type': 'application/json'
            }
        });

        console.log('Response Data:', response.data); //aqui me arroja error en el response
        return response.data;
    } catch (error) {
        throw error;
    }
}



function createAESEncryption22(keyHex) {
    const blockSize = 16; // AES block size is 16 bytes
    const key = Buffer.from(keyHex, 'hex');

    function pkcs7Pad(text) {
        const pad = blockSize - (text.length % blockSize);
        const padding = Buffer.alloc(pad, pad);
        return Buffer.concat([text, padding]);
    }

    function pkcs7Unpad(text) {
        const pad = text[text.length - 1];
        return text.slice(0, -pad);
    }

    function encrypt(plaintext) {
        const iv = crypto.randomBytes(blockSize);
        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
        let encrypted = cipher.update(pkcs7Pad(Buffer.from(plaintext, 'utf-8')));
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const encryptedText = Buffer.concat([iv, encrypted]).toString('base64');
        return encryptedText;
    }

    function decrypt(encodedData) {
        try {
            const encodedBuffer = Buffer.from(encodedData, 'base64');
            const iv = encodedBuffer.slice(0, blockSize);
            const ciphertext = encodedBuffer.slice(blockSize);
            const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            const decryptedText = pkcs7Unpad(decrypted).toString('utf-8');
            return decryptedText;
        } catch (error) {
            return null;
        }
    }

    return { encrypt, decrypt };
}

function v2aes(keyHex) {
    const blockSize = 16; // AES block size is 16 bytes
    const key = Buffer.from(keyHex, 'hex');

    function pkcs5Pad(text) {
        const pad = blockSize - (text.length % blockSize);
        const padding = Buffer.alloc(pad, pad);
        return Buffer.concat([text, padding]);
    }

    function pkcs5Unpad(text) {
        const pad = text[text.length - 1];
        return text.slice(0, -pad);
    }

    function encrypt(plaintext) {
        const iv = crypto.randomBytes(blockSize);
        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
        let encrypted = cipher.update(pkcs5Pad(Buffer.from(plaintext, 'utf-8')));
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const encryptedText = Buffer.concat([iv, encrypted]).toString('base64');
        return encryptedText;
    }

    function decrypt(encodedData) {
        try {
            const encodedBuffer = Buffer.from(encodedData, 'base64');
            const iv = encodedBuffer.slice(0, blockSize);
            const ciphertext = encodedBuffer.slice(blockSize);
            const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            const decryptedText = pkcs5Unpad(decrypted).toString('utf-8');
            return decryptedText;
        } catch (error) {
            return null;
        }
    }

    return { encrypt, decrypt };
}


function finalahorasi(keyHex) {
    if (keyHex.length !== 32) {
        throw new Error('Invalid key length for AES-128. Key must be 32 hexadecimal characters (16 bytes).');
    }
    const key = CryptoJS.enc.Hex.parse(keyHex);

    function encrypt(plaintext) {
        const iv = CryptoJS.lib.WordArray.random(16);
        const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
            iv: iv,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });
        const encryptedText = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
        return encryptedText;
    }

    function decrypt(encryptedData) {
        const encryptedBuffer = CryptoJS.enc.Base64.parse(encryptedData);
        const iv = CryptoJS.lib.WordArray.create(encryptedBuffer.words.slice(0, 4));
        const ciphertext = CryptoJS.lib.WordArray.create(encryptedBuffer.words.slice(4));

        const decrypted = CryptoJS.AES.decrypt({
            ciphertext: ciphertext
        }, key, {
            iv: iv,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });

        return decrypted.toString(CryptoJS.enc.Utf8);
    }

    return { encrypt, decrypt };
}
