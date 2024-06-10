const axios = require('axios');
const { generateBearerTokenFromCreds } = require("skyflow-node");
const crypto = require("crypto");

exports.skyflowmain = async (event) => {
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
        const data = JSON.parse(buf)

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

const flowBulk = async (requestBulk, keyIntegration) => {
    const jsonString = JSON.stringify(requestBulk);
    const aesEncryption = createAESEncryption(keyIntegration.seedAES);
    const requestBulkEncryptedData = aesEncryption.encrypt(jsonString);
    try {
        const responseBulkEncryptedData = await clientBulkFlow(requestBulkEncryptedData, keyIntegration.data0);
        const responseBulkDecryptedData = JSON.parse(aesEncryption.decrypt(responseBulkEncryptedData));
        const transactionStatus = responseBulkDecryptedData && 'CdResponse' in responseBulkDecryptedData && responseBulkDecryptedData.CdResponse.trim() === '0C' ? 'success' : 'declined';

        return {
            data: responseBulkDecryptedData,
            transactionStatus: transactionStatus
        };
    } catch (error) {
        throw error;
    }
};

const clientBulkFlow = async(encryptedData, data0) => {
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

const detokenizeCreditCardInfo = async (creditCard, event) => {
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