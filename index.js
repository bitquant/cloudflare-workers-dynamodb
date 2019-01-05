var SHA256 = require('crypto-js/sha256');
var HmacSHA256 = require('crypto-js/hmac-sha256');

var accessKey = null;
var secretKey = null;
var primaryKey = null;
var tableName = null;
var regionList = null;

function init(config) {
    accessKey = config.accessKey;
    secretKey = config.secretKey;
    primaryKey = config.primaryKey;
    tableName = config.tableName;
    regionList = config.regionList;
}

function getSignatureKey(key, dateStamp, regionName, serviceName) {
    var keyDate = HmacSHA256(dateStamp, "AWS4" + key);
    var keyRegion = HmacSHA256(regionName, keyDate);
    var keyService = HmacSHA256(serviceName, keyRegion);
    var keySigning = HmacSHA256("aws4_request", keyService)
    return keySigning;
}

function pad(number) {
    if (number < 10) {
        return '0' + number;
    }
    return number;
}

function getDates() {

    const date = new Date();

    const amzdate = date.getUTCFullYear() +
        ''  + pad(date.getUTCMonth() + 1) +
        ''  + pad(date.getUTCDate()) +
        'T' + pad(date.getUTCHours()) +
        ''  + pad(date.getUTCMinutes()) +
        ''  + pad(date.getUTCSeconds()) +
        'Z';

    const datestamp = date.getUTCFullYear() +
        '' + pad(date.getUTCMonth() + 1) +
        '' + pad(date.getUTCDate());

    return { amzdate, datestamp };
}


/*
  The signing algorithm is based on information from these pages

  https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
  https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
  https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
  https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
  https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
  https://www.npmjs.com/package/crypto-js
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.LowLevelAPI.html
  https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/dynamodb-api.pdf
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CurrentAPI.html
*/

function signAndSendRequest(region, target, body) {

    const { amzdate, datestamp } = getDates();

    const service = 'dynamodb';
    const host = `${service}.${region}.amazonaws.com`;
    const endpoint = `https://${host}`;

    const method = 'POST';
    const canonicalUri = '/';
    const canonicalQuerystring = '';
    const canonicalHeaders = `host:${host}\n` + `x-amz-date:${amzdate}\n`;
    const signedHeaders = 'host;x-amz-date';
    const payloadHash = SHA256(body);
    const algorithm = 'AWS4-HMAC-SHA256';

    const canonicalRequest = method + '\n' + canonicalUri + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + payloadHash;
    const credentialScope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request';
    const stringToSign = algorithm + '\n' +  amzdate + '\n' +  credentialScope + '\n' +  SHA256(canonicalRequest);

    const signingKey = getSignatureKey(secretKey, datestamp, region, service);
    const signature = HmacSHA256(stringToSign, signingKey);

    const authorizationHeader = algorithm + ' ' + 'Credential=' + accessKey + '/' + credentialScope + ', ' +  'SignedHeaders=' + signedHeaders + ', ' + 'Signature=' + signature;

    const params = {
        method: method,
        headers: {
            'Accept-Encoding': 'identity',
            "Content-Type": "application/x-amz-json-1.0",
            'Authorization': authorizationHeader,
            'X-Amz-Date': amzdate,
            'X-Amz-Target': `DynamoDB_20120810.${target}`
        },
        body: body
    };

    return fetch(endpoint, params);
}

function listTables(region) {
    return signAndSendRequest(region, 'ListTables', '{}');
}

async function getItem(key, waitUntil) {

    const requestObject = {
        "Key": { },
        "TableName": tableName
    }
    requestObject.Key[primaryKey] = { "S": key };

    const request = JSON.stringify(requestObject);

    const promiseMap = new Map();
    const startTime = new Date();

    for (const region of regionList) {
        const promise = signAndSendRequest(region, 'GetItem', request)
           .then(rsp => ({response: rsp, region: region}))
           .catch(ex => ({response: { ok: false, status: 999, statusText: ex}, region: region}))
        promiseMap.set(region, promise);
    }

    while (promiseMap.size > 0) {
        var { response, region } = await Promise.race([...promiseMap.values()]);
        promiseMap.delete(region);
        if (response.ok) {
            break;
        }
    }

    const endTime = new Date();

    if (!response.ok && promiseMap.size === 0) {
        throw new Error(`unable to get item: ${key}`)
    }

    //console.log(`Completed from region ${region}: ${response.status} ${response.statusText} ${endTime - startTime}`)

    const allResponsesComplete = async function (promiseMap) {
        while (promiseMap.size > 0) {
            const { response, region } = await Promise.race([...promiseMap.values()]);
            promiseMap.delete(region);
            const endTime = new Date();
            const responseTime = endTime - startTime;
            //console.log(`Status for region ${region}: ${response.status} ${response.statusText} ${responseTime}`)
        }
    }

    if (waitUntil !== undefined) {
        waitUntil(allResponsesComplete(promiseMap));
    }

    let responseBody = await response.json();
    let item = null;
    if (responseBody.Item && responseBody.Item.content) {
        item = responseBody.Item.content.S;
    }

    return item;
}


exports.init = init;
exports.listTables = listTables;
exports.get = getItem;
