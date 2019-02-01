var SHA256 = require('crypto-js/sha256');
var HmacSHA256 = require('crypto-js/hmac-sha256');
var uuidv4 = require('uuid/v4');

var accessKey = null;
var secretKey = null;
var primaryKey = null;
var sortKey = null;
var valueKey = null;
var tableName = null;
var regionList = null;

function init(config) {
    accessKey = config.accessKey;
    secretKey = config.secretKey;
    primaryKey = config.primaryKey;
    sortKey = config.sortKey;
    valueKey = config.valueKey;
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

async function getItemRace(pkey, skey, waitUntil) {

    const requestObject = {
        "Key": { },
        "TableName": tableName
    }
    requestObject.Key[primaryKey] = { "S": pkey };
    requestObject.Key[sortKey] = { "N": '' + skey };

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
        throw new Error(`unable to get item: ${pkey}`)
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
    if (responseBody.Item && responseBody.Item[valueKey]) {
        item = responseBody.Item[valueKey].S;
    }

    return { value: item, region }
}

async function getDynamoItem(pkey, skey, type, region) {

    const requestObject = {
        "TableName": tableName,
        "Key": { }
    }
    requestObject.Key[primaryKey] = { "S": pkey };
    requestObject.Key[sortKey] = { "N": '' + skey };

    const request = JSON.stringify(requestObject);
    //console.log('getDynamoItem() body ' + request)

    const firstRegion = (region === undefined) ? regionList[0] : region; // TODO: assign a primary read/write region

    const promise = signAndSendRequest(firstRegion, 'GetItem', request)
        .then(rsp => ({response: rsp}))
        .catch(ex => ({response: { ok: false, status: 999, statusText: ex.toString()}}))

    var { response } = await promise;

    if (!response.ok) {
        throw new Error(`unable to get item ${pkey} ${skey} because of error ${response.statusText}`);
    }

    let responseBody = await response.json();
    let item = null;
    if (responseBody.Item && responseBody.Item[valueKey]) {
        if (type === 'arrayBuffer') {
            let base64text = responseBody.Item[valueKey].B;
            let binaryString = atob(base64text);
            var byteArray = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                byteArray[i] = binaryString.charCodeAt(i);
            }
            item = byteArray;
        }
        else {
            item = responseBody.Item[valueKey].S;
        }
    }

    return item;
}

async function putDynamoItem(pkey, skey, value) {

    let itemValue = (value instanceof Uint8Array) ?
        { "B": btoa(String.fromCharCode(...value)) } : { "S": value };

    const requestObject = {
        "TableName": tableName,
        "Item": { }
    }
    requestObject.Item[primaryKey] = { "S": pkey };
    requestObject.Item[sortKey] = { "N": '' + skey };
    requestObject.Item[valueKey] = itemValue;

    const request = JSON.stringify(requestObject);
    //console.log('putDynamoItem() body ' + request)

    const firstRegion = regionList[0]; // TODO: assign a primary write region

    const promise = signAndSendRequest(firstRegion, 'PutItem', request)
        .then(rsp => ({response: rsp, region: firstRegion}))
        .catch(ex => ({response: { ok: false, status: 999, statusText: ex.toString()}, region: firstRegion}))

    var { response, region } = await promise;

    if (!response.ok) {
        throw new Error(`unable to put item ${pkey} ${skey} because of error ${response.statusText}`);
    }

    return undefined;
}

async function deleteDynamoItem(pkey, skey) {

    const requestObject = {
        "TableName": tableName,
        "Key": { }
    }
    requestObject.Key[primaryKey] = { "S": pkey };
    requestObject.Key[sortKey] = { "N": '' + skey };

    const request = JSON.stringify(requestObject);
    //console.log('deleteDynamoItem() ' + request)

    const firstRegion = regionList[0]; // TODO: assign a primary write region

    const promise = signAndSendRequest(firstRegion, 'DeleteItem', request)
        .then(rsp => ({response: rsp, region: firstRegion}))
        .catch(ex => ({response: { ok: false, status: 999, statusText: ex.toString()}, region: firstRegion}))

    var { response, region } = await promise;

    if (!response.ok) {
        throw new Error(`unable to delete item ${pkey} ${skey} because of error ${response.statusText}`);
    }

    return undefined;
}

function parseBlockMeta(value) {
    let blockId = value.slice(3, 39);
    let blockCount = parseInt(value.slice(47), 10);
    return { blockId, blockCount };
}

var BLOCK_SIZE = 400000;
var BLOCK_REGEX = /^id=[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12};length=[0-9]{1,}$/

async function getItem(key, waitUntil) {

    let {value, region} = await getItemRace(key, 0, waitUntil);

    //console.log(`race winner: ${region} with value ${value}`);

    if (value === null || value.search(BLOCK_REGEX) === -1) {
        return value;
    }

    let { blockId, blockCount } = parseBlockMeta(value);
    let promiseList = [];

    for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
        let blockPromise = getDynamoItem(blockId, blockIndex, 'arrayBuffer', region)
        promiseList.push(blockPromise)
    }

    let blockList = await Promise.all(promiseList);
    let finalValue = '';
    let byteArraySize = 0;

    for (let blockData of blockList) {
        if (blockData === null) {
            let err = new Error(`key '${key}' has missing data blocks and needs deletion`);
            err.blockRecord = value;
            throw err;
        }
        if (blockData instanceof Uint8Array) {
            byteArraySize += blockData.byteLength;
        }
        else {
            finalValue += blockData;
        }
    }

    if (byteArraySize > 0) {
        let resultArray = new Uint8Array(byteArraySize);
        let offset = 0;
        for (let blockData of blockList) {
            resultArray.set(blockData, offset);
            offset += blockData.byteLength;
        }
        let decoder = new TextDecoder();
        finalValue = decoder.decode(resultArray);
    }

    return finalValue;
}

async function putItem(key, value) {

    let oldValue = await getDynamoItem(key, 0);
    let oldBlock = undefined;

    if (oldValue !== null && oldValue.search(BLOCK_REGEX) === 0) {
        oldBlock = oldValue;
    }

    let encoder = new TextEncoder();
    let encoded = encoder.encode(value);

    if (encoded.length <= BLOCK_SIZE) {
        await putDynamoItem(key, '0', value);
        return oldBlock;
    }

    let blockList  = [];
    let blocks = Math.floor(encoded.length / BLOCK_SIZE);
    let lastBlock = (encoded.length % BLOCK_SIZE) > 0 ? 1 : 0;
    let totalBlocks = blocks + lastBlock;

    for (let i = 0; i < totalBlocks; i++) {
        let startIndex = i * BLOCK_SIZE;
        let endIndex = startIndex + BLOCK_SIZE;
        let block = encoded.slice(startIndex, endIndex);
        blockList.push(block);
    }

    let blockId = uuidv4();
    let blockIndex = 0;

    for (let block of blockList) {
        try {
            await putDynamoItem(blockId, blockIndex, block);
        }
        catch (ex) {
            throw new Error(`${blockId} ${blockIndex} block put error: ${ex.message}`)
        }
        blockIndex++;
    }

    await putDynamoItem(key, 0, `id=${blockId};length=${blockList.length}`);

    return oldBlock;
}

async function delItem(key) {

    let value = await getDynamoItem(key, 0);

    if (value === null) {
        return false;
    }

    if (value.search(BLOCK_REGEX) === -1) {
        return deleteDynamoItem(key, 0);
    }

    let { blockId, blockCount } = parseBlockMeta(value);

    for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
        await deleteDynamoItem(blockId, blockIndex);
    }

    return deleteDynamoItem(key, 0);
}

async function clean(block) {

    let { blockId, blockCount } = parseBlockMeta(block);

    for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
        await deleteDynamoItem(blockId, blockIndex);
    }
}

exports.init = init;
exports.listTables = listTables;
exports.get = getItem;
exports.put = putItem;
exports.del = delItem;
exports.clean = clean;
