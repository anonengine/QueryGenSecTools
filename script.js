function showTab(tabName) {
    const splunkTab = document.getElementById('splunk');
    const microsoftTab = document.getElementById('microsoft');
    if (tabName === 'splunk') {
        splunkTab.style.display = 'block';
        microsoftTab.style.display = 'none';
        document.getElementById('queryType').style.display = 'block';
        document.getElementById('msQueryType').style.display = 'none';
    } else if (tabName === 'microsoft') {
        splunkTab.style.display = 'none';
        microsoftTab.style.display = 'block';
        document.getElementById('queryType').style.display = 'none';
        document.getElementById('msQueryType').style.display = 'block';
    }
    updatePlaceholder();
}

function updatePlaceholder() {
    const isSplunk = document.getElementById('splunk').style.display !== 'none';
    const queryType = isSplunk ? document.getElementById('queryType').value : document.getElementById('msQueryType').value;
    const inputField = document.getElementById('inputField');
    
    switch(queryType) {
        case 'domainTraffic':
        case 'domainTrafficTable':
            inputField.placeholder = 'Enter URLs or domains here (one per line)...';
            break;
        case 'emailRecipients':
            inputField.placeholder = 'Enter email address to search for...';
            break;
        case 'availableLogs':
            inputField.placeholder = 'No input required for this query.';
            break;
        case 'mdmDeviceLookup':
            inputField.placeholder = 'Enter IP address to search for...';
            break;
        case 'urlClickEvents':
        case 'deviceNetworkEvents':
            inputField.placeholder = 'Enter URLs here (one per line)...';
            break;
        case 'fileHashSearch':
            inputField.placeholder = 'Enter file hashes here (one per line)...';
            break;
        case 'specificFileSearch':
            inputField.placeholder = 'Enter file names here (one per line)...';
            break;
    }
}

function extractDomain(url) {
    try {
        const domain = url.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "")
                          .split('/')[0]
                          .split('?')[0]
                          .split('#')[0];
        return domain.toLowerCase();
    } catch (e) {
        console.error("Error extracting domain:", e);
        return url;
    }
}

function generateQuery() {
    const isSplunk = document.getElementById('splunk').style.display !== 'none';
    const queryType = isSplunk ? document.getElementById('queryType').value : document.getElementById('msQueryType').value;
    const inputField = document.getElementById('inputField').value;
    const outputQuery = document.getElementById('outputQuery').querySelector('code');
    let query = '';

    const inputs = inputField.split(/\r?\n/).map(input => input.trim()).filter(input => input !== '');

    if (isSplunk) {
        switch(queryType) {
            case 'domainTraffic':
            case 'domainTrafficTable':
                const domains = inputs.map(extractDomain).filter((value, index, self) => self.indexOf(value) === index);
                if (domains.length === 0) {
                    outputQuery.textContent = 'Please enter at least one URL or domain.';
                    return;
                }
                const domainQuery = domains.join(' OR ');
                query = `index=firewall ${domainQuery}`;
                if (queryType === 'domainTrafficTable') {
                    query += ` | table _time,date,index,date,src,src_host,src_ip,msg,srccountry,dstcountry,src_host,dstip,direction,dst_ip,action,file_name,dstport,dst_port,hostname,url,policyname,bytes_in,bytes_out,dstinetsvc,objURl,referralurl,direction,created,cfgpath,cfgattrable,user | dedup _time`;
                }
                break;
            case 'emailRecipients':
                const emailAddress = inputField.trim();
                if (emailAddress) {
                    query = `index=email ${emailAddress} | table _time,RecipientAddress,SenderAddress,Subject | dedup RecipientAddress`;
                } else {
                    outputQuery.textContent = 'Please enter an email address.';
                    return;
                }
                break;
            case 'availableLogs':
                query = '| eventcount summarize=false index=*';
                break;
            case 'mdmDeviceLookup':
                const ipAddress = inputField.trim();
                if (ipAddress) {
                    query = `AADSignInEventsBeta\n| where IPAddress contains "${ipAddress}"`;
                } else {
                    outputQuery.textContent = 'Please enter an IP address.';
                    return;
                }
                break;
        }
    } else {
        switch(queryType) {
            case 'urlClickEvents':
                if (inputs.length === 0) {
                    outputQuery.textContent = 'Please enter at least one URL.';
                    return;
                }
                const urlConditions = inputs.map(url => `Url contains "${url}"`).join(' or ');
                query = `UrlClickEvents\n| where ${urlConditions}`;
                break;
            case 'deviceNetworkEvents':
                if (inputs.length === 0) {
                    outputQuery.textContent = 'Please enter at least one URL.';
                    return;
                }
                query = `DeviceNetworkEvents\n| where ${inputs.map(url => `RemoteUrl contains "${url}"`).join(' or ')}`;
                break;
            case 'fileHashSearch':
                if (inputs.length === 0) {
                    outputQuery.textContent = 'Please enter at least one file hash.';
                    return;
                }
                const hashConditions = inputs.map(hash => `SHA1 == "${hash}" or SHA256 == "${hash}" or MD5 == "${hash}"`).join(' or ');
                query = `DeviceFileEvents
| where Timestamp > ago(30d) // Adjust the time range as needed
| where ${hashConditions}
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256, MD5, InitiatingProcessAccountName
| sort by Timestamp desc`;
                break;
            case 'specificFileSearch':
                if (inputs.length === 0) {
                    outputQuery.textContent = 'Please enter at least one file name.';
                    return;
                }
                const fileConditions = inputs.map(file => `FileName == "${file}"`).join(' or ');
                query = `DeviceFileEvents
| where ${fileConditions}
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| order by Timestamp desc`;
                break;
        }
    }

    outputQuery.textContent = query;
}

function copyToClipboard() {
    const outputQuery = document.getElementById('outputQuery').querySelector('code');
    navigator.clipboard.writeText(outputQuery.textContent)
        .then(() => alert('Query copied to clipboard'))
        .catch(err => alert('Failed to copy text: ', err));
}

function defangUrls() {
    const inputField = document.getElementById('inputField');
    const urls = inputField.value.split('\n');
    const defangedUrls = urls.map(url => {
        return url.replace(/\./g, '[.]')
                  .replace(/http:/g, 'hxxp:')
                  .replace(/https:/g, 'hxxps:');
    });
    inputField.value = defangedUrls.join('\n');
}

// Initial setup
document.addEventListener('DOMContentLoaded', function() {
    showTab('splunk'); // Start with Splunk tab
    document.getElementById('queryType').addEventListener('change', updatePlaceholder);
    document.getElementById('msQueryType').addEventListener('change', updatePlaceholder);
});
