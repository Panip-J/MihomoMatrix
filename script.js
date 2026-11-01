function main(config, profileName) {
  const proxies = config.proxies || [];
  const proxyNames = proxies.map(p => p.name);

  const emojiIcon = code => `https://github.githubassets.com/images/icons/emoji/unicode/${code}.png?v8`;
  const isIP = str => /^(?:\d{1,3}\.){3}\d{1,3}$|^[a-fA-F0-9:]+$/.test(str);
  const tlsTypes = ['trojan', 'vless', 'vmess', 'anytls', 'tuic', 'hysteria', 'hysteria2'];

  proxies.forEach(p => {
    if (tlsTypes.includes(p.type) && !p['client-fingerprint']) {
      p['client-fingerprint'] = 'chrome';
    }
  });

  const serverDomains = proxies
    .map(p => p.server)
    .filter(s => s && typeof s === 'string' && !isIP(s));

  const baseFakeIpFilter = [
    '*.lan', '*.localdomain', '*.example', '*.invalid', '*.localhost', '*.test', '*.local', '*.home.arpa',
    '+.msftconnecttest.com', '+.msftncsi.com',
    'time.*.com', 'time.*.gov', 'time.*.apple.com', 'time.*.edu.cn', '+.pool.ntp.org', 'time1.cloud.tencent.com',
    'stun.*.*', 'stun.*.*.*', '+.trafficmanager.net',
    'localhost.ptlogin2.qq.com', 'localhost.sec.qq.com', 'localhost.work.weixin.qq.com',
    'ddns.oray.com', 'v4.66666.host', 'myip.ipip.net', 'v4.666666.host', '4.ipw.cn', 'ip.3322.net',
    'v6.66666.host', 'myip6.ipip.net', '6.ipw.cn', 'v6.666666.host'
  ];
  const origFakeIpFilter = (config.dns && config.dns['fake-ip-filter']) || [];
  const finalFakeIpFilter = Array.from(new Set([...baseFakeIpFilter, ...serverDomains, ...origFakeIpFilter]));

  const origProxyServerDns = (config.dns && config.dns['proxy-server-nameserver']) || [];
  const origProxyServerPolicy = (config.dns && config.dns['proxy-server-nameserver-policy']) || {};
  const origNameserverPolicy = (config.dns && config.dns['nameserver-policy']) || {};
  const defaultProxyServerDns = ['223.5.5.5', '119.29.29.29'];

  const proxyServerPolicy = Object.assign({}, origProxyServerPolicy);
  if (origProxyServerDns.length > 0 && serverDomains.length > 0) {
    const customDns = origProxyServerDns.length === 1 ? origProxyServerDns[0] : origProxyServerDns;
    serverDomains.forEach(domain => {
      if (!proxyServerPolicy[domain]) {
        proxyServerPolicy[domain] = customDns;
      }
    });
  }

  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['prefer-ipv4'] = true;
  config.profile = Object.assign({}, config.profile, { 'store-selected': true });

  config.sniffer = {
    enable: true,
    'parse-pure-ip': true,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, '8080-8880'], 'override-destination': true }
    },
    'skip-domain': ['Mijia Cloud', 'dlg.io.mi.com', '+.apple.com']
  };

  config.dns = {
    enable: true,
    ipv6: true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-range6': 'fdfe:dcba:9876::1/64',
    'use-hosts': true,
    'respect-rules': true,
    'cache-algorithm': 'arc',
    'fake-ip-filter': finalFakeIpFilter,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': defaultProxyServerDns,
    nameserver: ['223.5.5.5', '119.29.29.29'],
    fallback: ['1.1.1.1', '8.8.8.8'],
    'fallback-filter': {
      geoip: true,
      'geoip-code': 'CN',
      ipcidr: ['240.0.0.0/4']
    }
  };
  if (Object.keys(proxyServerPolicy).length > 0) {
    config.dns['proxy-server-nameserver-policy'] = proxyServerPolicy;
  }
  if (Object.keys(origNameserverPolicy).length > 0) {
    config.dns['nameserver-policy'] = origNameserverPolicy;
  }

  const ruleSet = (category, file) => ({
    type: 'http',
    behavior: 'classical',
    interval: 86400,
    url: `https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/${category}/${file}.yaml`,
    path: `./ruleset/${file}.yaml`
  });
  config['rule-providers'] = {
    Lan: ruleSet('Lan', 'Lan_No_Resolve'),
    ChinaMax: ruleSet('ChinaMax', 'ChinaMax_Classical_No_Resolve'),
    SteamCN: ruleSet('SteamCN', 'SteamCN_No_Resolve'),
    Steam: ruleSet('Steam', 'Steam_No_Resolve'),
    Epic: ruleSet('Epic', 'Epic_No_Resolve'),
    Wikipedia: ruleSet('Wikipedia', 'Wikipedia_No_Resolve'),
    Global: ruleSet('Global', 'Global_Classical_No_Resolve')
  };

  const countryDefs = [
    { name: 'HKG', code: '1f1ed-1f1f0', regex: /(?:香港|HK(?![a-zA-Z])|HongKong|Hong Kong)/i },
    { name: 'MAC', code: '1f1f2-1f1f4', regex: /(?:澳门|MO(?![a-zA-Z])|Macau|Macao)/i },
    { name: 'TWN', code: '1f1f9-1f1fc', regex: /(?:台湾|TW(?![a-zA-Z])|Taiwan)/i },
    { name: 'JPN', code: '1f1ef-1f1f5', regex: /(?:日本|JP(?![a-zA-Z])|Japan)/i },
    { name: 'KOR', code: '1f1f0-1f1f7', regex: /(?:韩国|KR(?![a-zA-Z])|Korea)/i },
    { name: 'SGP', code: '1f1f8-1f1ec', regex: /(?:新加坡|SG(?![a-zA-Z])|Singapore)/i },
    { name: 'MYS', code: '1f1f2-1f1fe', regex: /(?:马来|MY(?![a-zA-Z])|Malaysia)/i },
    { name: 'THA', code: '1f1f9-1f1ed', regex: /(?:泰国|TH(?![a-zA-Z])|Thailand)/i },
    { name: 'VNM', code: '1f1fb-1f1f3', regex: /(?:越南|VN(?![a-zA-Z])|Vietnam)/i },
    { name: 'IDN', code: '1f1ee-1f1e9', regex: /(?:印尼|印度尼西亚|ID(?![a-zA-Z])|Indonesia)/i },
    { name: 'IND', code: '1f1ee-1f1f3', regex: /(?:(?<!印)印度(?!尼西亚)|IN(?![a-zA-Z])|India)/i },
    { name: 'ARE', code: '1f1e6-1f1ea', regex: /(?:阿拉伯联合酋长国|阿联酋|迪拜|阿布扎比|AE(?![a-zA-Z])|UAE|United Arab Emirates)/i },
    { name: 'USA', code: '1f1fa-1f1f8', regex: /(?:美国|US(?![a-zA-Z])|UnitedStates|United States)/i },
    { name: 'CAN', code: '1f1e8-1f1e6', regex: /(?:加拿大|CA(?![a-zA-Z])|Canada)/i },
    { name: 'MEX', code: '1f1f2-1f1fd', regex: /(?:墨西哥|MX(?![a-zA-Z])|Mexico)/i },
    { name: 'BRA', code: '1f1e7-1f1f7', regex: /(?:巴西|BR(?![a-zA-Z])|Brazil)/i },
    { name: 'UKR', code: '1f1fa-1f1e6', regex: /(?:乌克兰|UA(?![a-zA-Z])|Ukraine)/i },
    { name: 'ROU', code: '1f1f7-1f1f4', regex: /(?:罗马尼亚|RO(?![a-zA-Z])|Romania)/i },
    { name: 'LTU', code: '1f1f1-1f1f9', regex: /(?:立陶宛|LT(?![a-zA-Z])|Lithuania)/i },
    { name: 'ITA', code: '1f1ee-1f1f9', regex: /(?:意大利|IT(?![a-zA-Z])|Italy)/i },
    { name: 'TUR', code: '1f1f9-1f1f7', regex: /(?:土耳其|TR(?![a-zA-Z])|Turkey)/i },
    { name: 'GBR', code: '1f1ec-1f1e7', regex: /(?:英国|UK(?![a-zA-Z])|GreatBritain|UnitedKingdom)/i },
    { name: 'DEU', code: '1f1e9-1f1ea', regex: /(?:德国|DE(?![a-zA-Z])|Germany)/i },
    { name: 'FRA', code: '1f1eb-1f1f7', regex: /(?:法国|FR(?![a-zA-Z])|France)/i },
    { name: 'NLD', code: '1f1f3-1f1f1', regex: /(?:荷兰|NL(?![a-zA-Z])|Netherlands)/i },
    { name: 'SWE', code: '1f1f8-1f1ea', regex: /(?:瑞典|SE(?![a-zA-Z])|Sweden)/i },
    { name: 'AUS', code: '1f1e6-1f1fa', regex: /(?:澳大利亚|澳洲|AU(?![a-zA-Z])|Australia)/i },
    { name: 'NGA', code: '1f1f3-1f1ec', regex: /(?:尼日利亚|NG(?![a-zA-Z])|Nigeria)/i }
  ];

  const countryBuckets = new Map(countryDefs.map(def => [def.name, []]));
  const otherNames = [];
  proxyNames.forEach(name => {
    const hit = countryDefs.find(def => def.regex.test(name));
    if (hit) {
      countryBuckets.get(hit.name).push(name);
    } else {
      otherNames.push(name);
    }
  });

  const countryGroups = countryDefs.map(def => ({
    name: def.name,
    type: 'select',
    proxies: countryBuckets.get(def.name).length > 0 ? countryBuckets.get(def.name) : ['DIRECT'],
    icon: emojiIcon(def.code)
  }));
  countryGroups.push({
    name: 'OTH',
    type: 'select',
    proxies: otherNames.length > 0 ? otherNames : ['DIRECT'],
    icon: emojiIcon('1f3f4-2620')
  });

  const defaultProxies = [
    'DIRECT', 'ALL',
    'HKG', 'MAC', 'TWN', 'JPN', 'KOR',
    'SGP', 'MYS', 'THA', 'VNM', 'IDN', 'IND', 'ARE',
    'USA', 'CAN', 'MEX', 'BRA',
    'UKR', 'ROU', 'LTU', 'ITA', 'TUR', 'GBR', 'DEU', 'FRA', 'NLD', 'SWE',
    'AUS', 'NGA', 'OTH'
  ];
  const coreGroupDefs = [
    { name: 'DEFAULT', code: '1f680', proxies: defaultProxies },
    { name: 'ALL', code: '1f30f', proxies: proxyNames.length > 0 ? proxyNames : ['DIRECT'] },
    { name: 'STORE', code: '1f3ae', proxies: ['HKG', 'DEFAULT', 'DIRECT'] },
    { name: 'WIKI', code: '1f4da', proxies: ['HKG', 'DEFAULT', 'DIRECT'] },
    { name: 'PIKPAK', code: '1f5c3', proxies: ['HKG', 'DEFAULT', 'DIRECT'] },
    { name: 'SRGB', code: '1f4a1', proxies: ['USA', 'DEFAULT', 'DIRECT'] },
    { name: 'SLIP', code: '1f41f', proxies: ['DEFAULT', 'DIRECT'] }
  ];
  const coreGroups = {};
  coreGroupDefs.forEach(def => {
    coreGroups[def.name] = { name: def.name, type: 'select', proxies: def.proxies, icon: emojiIcon(def.code) };
  });

  // 每条路由 = [类型, 匹配值, 目标组]，按数组顺序即规则优先级，改一条只动一行
  const routeTable = [
    ['DOMAIN-SUFFIX', 'local', 'DIRECT'],
    ['DOMAIN-SUFFIX', 'lan', 'DIRECT'],
    ['RULE-SET', 'Lan', 'DIRECT'],
    ['DOMAIN-SUFFIX', 'moegirl.org.cn', 'WIKI'],
    ['RULE-SET', 'ChinaMax', 'DIRECT'],
    ['GEOIP', 'CN', 'DIRECT'],
    ['DOMAIN-SUFFIX', 'acgrip.com', 'DIRECT'],
    ['DOMAIN-SUFFIX', 'mineru.net', 'DIRECT'],
    ['DOMAIN-SUFFIX', 'openxlab.org.cn', 'DIRECT'],
    ['RULE-SET', 'SteamCN', 'DIRECT'],
    ['RULE-SET', 'Steam', 'STORE'],
    ['RULE-SET', 'Epic', 'STORE'],
    ['RULE-SET', 'Wikipedia', 'WIKI'],
    ['DOMAIN-KEYWORD', 'pikpak', 'PIKPAK'],
    ['DOMAIN-SUFFIX', 'signalrgb.com', 'SRGB'],
    ['RULE-SET', 'Global', 'DEFAULT'],
    ['DOMAIN-SUFFIX', 'opencode.ai', 'DEFAULT'],
    ['MATCH', '', 'SLIP']
  ];

  const knownTargets = new Set(['DIRECT', 'REJECT', ...countryDefs.map(def => def.name), ...Object.keys(coreGroups)]);
  routeTable.forEach(([type, value, target]) => {
    if (!knownTargets.has(target)) {
      throw new Error(`规则目标组不存在: ${type},${value},${target}`);
    }
    if (type === 'RULE-SET' && !config['rule-providers'][value]) {
      throw new Error(`规则集未定义: ${value}`);
    }
  });
  config.rules = routeTable.map(([type, value, target]) => (type === 'MATCH' ? `MATCH,${target}` : `${type},${value},${target}`));

  config['proxy-groups'] = [
    coreGroups.DEFAULT,
    coreGroups.ALL,
    ...countryGroups,
    coreGroups.STORE,
    coreGroups.WIKI,
    coreGroups.PIKPAK,
    coreGroups.SRGB,
    coreGroups.SLIP
  ];

  return config;
}
