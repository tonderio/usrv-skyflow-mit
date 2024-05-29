const axios = require('axios');
const { generateBearerTokenFromCreds } = require("skyflow-node");
const CryptoJS = require('crypto-js');

exports.skyflowmain = async function (event) {
    let functionResponse = {
        bodyBytes: "",
        headers: {
            "Content-Type": "application/json",
            "Error-From-Client": "false",
        },
        statusCode: 200,
    };
    try {
        const buf = Buffer.from(event.BodyContent, 'base64')
        const data = JSON.parse(buf.toString())

        const detokenizedCreditCard = await detokenizeCreditCardInfo(data.requestBulk.Transaction.Creditcard, event);
        if (!detokenizedCreditCard.success) {
            functionResponse.bodyBytes = JSON.stringify(detokenizedCreditCard)
            functionResponse.statusCode = 500
            return functionResponse
        }

        data.requestBulk.Transaction.Creditcard.Number = detokenizedCreditCard.Number;
        data.requestBulk.Transaction.Creditcard.ExpMonth = detokenizedCreditCard.ExpMonth;
        data.requestBulk.Transaction.Creditcard.ExpYear = detokenizedCreditCard.ExpYear;
        data.requestBulk.Transaction.Creditcard.CvvCsc = detokenizedCreditCard.CvvCsc;

        const responseBulk = await flowBulk(data.requestBulk, data.keyIntegration);

        functionResponse.bodyBytes = JSON.stringify(responseBulk);
        return functionResponse

    } catch (err) {
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

async function flowBulk(requestBulk, keyIntegration) {
    const jsonString = JSON.stringify(requestBulk);
    const aesEncryption = createAESEncryption(keyIntegration.seedAES);
    const requestBulkEncryptedData = aesEncryption.encrypt(jsonString);
    try {
        const responseBulkEncryptedData = await clientBulkFlow(requestBulkEncryptedData, keyIntegration.data0);
        const responseBulkDecryptedData = aesEncryption.decrypt(responseBulkEncryptedData);
        return responseBulkDecryptedData;
    } catch (error) {
        throw error;
    }
};

async function clientBulkFlow(encryptedData, data0) {
    const url = process.env.pspUrl;
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

async function detokenizeCreditCardInfo(creditCard, event) {
    const tokenizedFields = [
        { fieldName: "Number", fieldValue: creditCard.Number },
        { fieldName: "ExpMonth", fieldValue: creditCard.ExpMonth },
        { fieldName: "ExpYear", fieldValue: creditCard.ExpYear },
        { fieldName: "CvvCsc", fieldValue: creditCard.CvvCsc }
    ];

    const { credentials, vaultURL, vaultID } = process.env;
    const requestId = event.Headers?.["X-Request-Id"]?.[0];
    const detokenizedData = await getDetokenizedFields(
        tokenizedFields,
        credentials,
        vaultURL,
        vaultID,
        requestId
    );
    return detokenizedData;
}


const getDetokenizedFields = async (
    tokenizedFields,
    credentials,
    vaultURL,
    vaultID,
    requestId
) => {
    const token = await generateBearerTokenFromCreds(credentials);
    const endpoint = `${vaultURL}/v1/vaults/${vaultID}/detokenize`;
    const detokenizationParameters = tokenizedFields.map(field => ({
        token: field.fieldValue,
        redaction: "PLAIN_TEXT",
    }));

    try {
        const response = await axios.post(
            endpoint,
            {
                detokenizationParameters: detokenizationParameters,
            },
            {
                headers: {
                    "x-request-id": requestId,
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token.accessToken}`
                },
            }
        );

        const detokenizedData = {};
        response.data.records.forEach(record => {
            const fieldName = tokenizedFields.find(f => f.fieldValue === record.token).fieldName;
            detokenizedData[fieldName] = record.value;
        });

        return {
            ...detokenizedData,
            success: true,
        };
    } catch (error) {
        console.error('Detokenization error:', error);
        return {
            error: error.response?.data || "Detokenization failed",
            success: false,
        };
    }
};