async function fetchRulesFromBackend() {
  try {
    const response = await fetch('http://127.0.0.1:5000/api/firewall-rules');
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.json();
    return {
      blockedDomains: data.blockedDomains || [],
      blockedIPs: data.blockedIPs || []
    };
  } catch (error) {
    console.error('Error fetching firewall rules:', error.message);
    return { blockedDomains: [], blockedIPs: [] };
  }
}

function convertToPunycode(domain) {
  try {
    const url = new URL(`http://${domain}`);
    return url.hostname;
  } catch (error) {
    console.error('Error converting to Punycode:', domain, error);
    return null;
  }
}

function updateBlockingRules({ blockedDomains, blockedIPs }) {
  const blockingRules = [];

  blockedDomains = blockedDomains || [];
  blockedIPs = blockedIPs || [];

  blockedDomains.forEach((domain, index) => {
    const punycodeDomain = convertToPunycode(domain);
    if (punycodeDomain) {
      blockingRules.push({
        id: index + 1,
        priority: 1,
        action: { type: "block" },
        condition: {
          urlFilter: `*://${punycodeDomain}/*`,
          resourceTypes: ["main_frame"]
        }
      });
    }
  });

  blockedIPs.forEach((ip, index) => {
    blockingRules.push({
      id: blockedDomains.length + index + 1,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `*://${ip}/*`,
        resourceTypes: ["main_frame"]
      }
    });
  });

  chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
    const existingRuleIds = existingRules.map(rule => rule.id);

    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingRuleIds,
      addRules: blockingRules
    }, () => {
      console.log('Firewall rules updated:', { blockedDomains, blockedIPs });
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  fetchRulesFromBackend().then(rules => {
    updateBlockingRules(rules);
  });

  chrome.alarms.create('updateRules', { periodInMinutes: 60 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'updateRules') {
    fetchRulesFromBackend().then(rules => {
      updateBlockingRules(rules);
    });
  }
});

chrome.runtime.onStartup.addListener(() => {
  fetchRulesFromBackend().then(rules => {
    updateBlockingRules(rules);
  });
});

async function analyzeUrlWithBackend(url) {
  try {
    const response = await fetch('http://127.0.0.1:5000/api/scan-url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();
    console.log(`URL analysis result: ${data.result}`);

    if (data.result === "Blocked by AI") {
      console.warn(`Blocked URL: ${url}`);
    } else {
      fetchRulesFromBackend().then(rules => {
        updateBlockingRules(rules);
      });
    }
  } catch (error) {
    console.error('Error analyzing URL:', error);
  }
}

// background.js

chrome.runtime.onInstalled.addListener(() => {
  // Reload the extension every X milliseconds
  const reloadTime = 1000; // 1 second

  setInterval(() => {
      chrome.runtime.reload();
  }, reloadTime);
});
