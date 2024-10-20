// Fetch blocked domains from backend
async function fetchBlockedDomains() {
  const response = await fetch('http://127.0.0.1:5000/api/firewall-rules');
  const data = await response.json();
  return data.blockedDomains;
}

// Render the domain list in the popup
function renderDomains(blockedDomains) {
  const domainList = document.getElementById('domain-list');
  domainList.innerHTML = '';

  blockedDomains.forEach(domain => {
    const domainItem = document.createElement('div');
    domainItem.classList.add('domain-item');

    const domainText = document.createElement('span');
    domainText.textContent = domain;

    const unblockButton = document.createElement('button');
    unblockButton.textContent = 'Unblock';
    unblockButton.onclick = () => unblockDomain(domain);

    domainItem.appendChild(domainText);
    domainItem.appendChild(unblockButton);

    domainList.appendChild(domainItem);
  });
}

// Unblock a domain by removing it from the blocked list
async function unblockDomain(domain) {
  const blockedDomains = await fetchBlockedDomains();
  const newBlockedDomains = blockedDomains.filter(d => d !== domain);

  // Update the backend with the new list of blocked domains
  await fetch('http://127.0.0.1:5000/api/update-blocked-domains', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ blockedDomains: newBlockedDomains })
  });

  // Re-render the list after update
  renderDomains(newBlockedDomains);
}

// Initialize the popup by fetching and rendering blocked domains
fetchBlockedDomains().then(blockedDomains => {
  renderDomains(blockedDomains);
});
