function main(config, profileName) {
  const proxies = config.proxies || [];
  const proxyNames = proxies.map(p => p.name);
  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['prefer-ipv4'] = true;
  config['profile'] = Object.assign({}, config['profile'], {
    'store-selected': true
  });
  config['sniffer'] = {
    enable: true,
    'parse-pure-ip': true,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, '8080-8880'], 'override-destination': true }
    },
    'skip-domain': [
      'Mijia Cloud',
      'dlg.io.mi.com',
      '+.apple.com'
    ]
  };
  config['dns'] = {
    enable: true,
    ipv6: true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-range6': 'fdfe:dcba:9876::1/64',
    'use-hosts': true,
    'respect-rules': true,
    'default-nameserver': [
      '223.5.5.5',
      '119.29.29.29'
    ],
    'proxy-server-nameserver': [
      '223.5.5.5',
      '119.29.29.29'
    ],
    nameserver: [
      '223.5.5.5',
      '119.29.29.29'
    ],
    fallback: [
      '1.1.1.1',
      '8.8.8.8'
    ],
    'fallback-filter': {
      geoip: true,
      'geoip-code': 'CN',
      ipcidr: [
        '240.0.0.0/4'
      ]
    }
  };
  config['rule-providers'] = {
    Lan: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Lan/Lan_No_Resolve.yaml',
      path: './ruleset/Lan_No_Resolve.yaml'
    },
    ChinaMax: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMax/ChinaMax_Classical_No_Resolve.yaml',
      path: './ruleset/ChinaMax_Classical_No_Resolve.yaml'
    },
    SteamCN: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/SteamCN/SteamCN_No_Resolve.yaml',
      path: './ruleset/SteamCN_No_Resolve.yaml'
    },
    Steam: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Steam/Steam_No_Resolve.yaml',
      path: './ruleset/Steam_No_Resolve.yaml'
    },
    Epic: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Epic/Epic_No_Resolve.yaml',
      path: './ruleset/Epic_No_Resolve.yaml'
    },
    Wikipedia: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Wikipedia/Wikipedia_No_Resolve.yaml',
      path: './ruleset/Wikipedia_No_Resolve.yaml'
    },
    Global: {
      type: 'http',
      behavior: 'classical',
      interval: 86400,
      url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global_Classical_No_Resolve.yaml',
      path: './ruleset/Global_Classical_No_Resolve.yaml'
    }
  };
  config['rules'] = [
    'DOMAIN-SUFFIX,local,DIRECT',
    'DOMAIN-SUFFIX,lan,DIRECT',
    'RULE-SET,Lan,DIRECT',
    'DOMAIN-SUFFIX,moegirl.org.cn,WIKI',
    'RULE-SET,ChinaMax,DIRECT',
    'GEOIP,CN,DIRECT',
    'DOMAIN-SUFFIX,acgrip.com,DIRECT',
    'DOMAIN-SUFFIX,mineru.net,DIRECT',
    'DOMAIN-SUFFIX,openxlab.org.cn,DIRECT',
    'RULE-SET,SteamCN,DIRECT',
    'RULE-SET,Steam,STORE',
    'RULE-SET,Epic,STORE',
    'RULE-SET,Wikipedia,WIKI',
    'DOMAIN-KEYWORD,pikpak,PIKPAK',
    'DOMAIN-SUFFIX,signalrgb.com,SRGB',
    'RULE-SET,Global,DEFAULT',
    'DOMAIN-SUFFIX,opencode.ai,DEFAULT',
    'MATCH,SLIP'
  ];
  const countryDefs = [
    { name: 'HKG', regex: /(?:香港|HK(?![a-zA-Z])|HongKong|Hong Kong)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1ed-1f1f0.png?v8' },
    { name: 'MAC', regex: /(?:澳门|MO(?![a-zA-Z])|Macau|Macao)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f2-1f1f4.png?v8' },
    { name: 'TWN', regex: /(?:台湾|TW(?![a-zA-Z])|Taiwan)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f9-1f1fc.png?v8' },
    { name: 'JPN', regex: /(?:日本|JP(?![a-zA-Z])|Japan)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1ef-1f1f5.png?v8' },
    { name: 'KOR', regex: /(?:韩国|KR(?![a-zA-Z])|Korea)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f0-1f1f7.png?v8' },
    { name: 'SGP', regex: /(?:新加坡|SG(?![a-zA-Z])|Singapore)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f8-1f1ec.png?v8' },
    { name: 'MYS', regex: /(?:马来|MY(?![a-zA-Z])|Malaysia)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f2-1f1fe.png?v8' },
    { name: 'THA', regex: /(?:泰国|TH(?![a-zA-Z])|Thailand)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f9-1f1ed.png?v8' },
    { name: 'VNM', regex: /(?:越南|VN(?![a-zA-Z])|Vietnam)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1fb-1f1f3.png?v8' },
    { name: 'IDN', regex: /(?:印尼|印度尼西亚|ID(?![a-zA-Z])|Indonesia)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1ee-1f1e9.png?v8' },
    { name: 'IND', regex: /(?:(?<!印)印度(?!尼西亚)|IN(?![a-zA-Z])|India)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1ee-1f1f3.png?v8' },
    { name: 'ARE', regex: /(?:阿拉伯联合酋长国|阿联酋|迪拜|阿布扎比|AE(?![a-zA-Z])|UAE|United Arab Emirates)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1e6-1f1ea.png?v8' },
    { name: 'USA', regex: /(?:美国|US(?![a-zA-Z])|UnitedStates|United States)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1fa-1f1f8.png?v8' },
    { name: 'CAN', regex: /(?:加拿大|CA(?![a-zA-Z])|Canada)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1e8-1f1e6.png?v8' },
    { name: 'MEX', regex: /(?:墨西哥|MX(?![a-zA-Z])|Mexico)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f2-1f1fd.png?v8' },
    { name: 'BRA', regex: /(?:巴西|BR(?![a-zA-Z])|Brazil)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1e7-1f1f7.png?v8' },
    { name: 'UKR', regex: /(?:乌克兰|UA(?![a-zA-Z])|Ukraine)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1fa-1f1e6.png?v8' },
    { name: 'ROU', regex: /(?:罗马尼亚|RO(?![a-zA-Z])|Romania)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f7-1f1f4.png?v8' },
    { name: 'LTU', regex: /(?:立陶宛|LT(?![a-zA-Z])|Lithuania)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f1-1f1f9.png?v8' },
    { name: 'ITA', regex: /(?:意大利|IT(?![a-zA-Z])|Italy)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1ee-1f1f9.png?v8' },
    { name: 'TUR', regex: /(?:土耳其|TR(?![a-zA-Z])|Turkey)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f9-1f1f7.png?v8' },
    { name: 'GBR', regex: /(?:英国|UK(?![a-zA-Z])|GreatBritain|UnitedKingdom)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1ec-1f1e7.png?v8' },
    { name: 'DEU', regex: /(?:德国|DE(?![a-zA-Z])|Germany)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1e9-1f1ea.png?v8' },
    { name: 'FRA', regex: /(?:法国|FR(?![a-zA-Z])|France)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1eb-1f1f7.png?v8' },
    { name: 'NLD', regex: /(?:荷兰|NL(?![a-zA-Z])|Netherlands)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f3-1f1f1.png?v8' },
    { name: 'SWE', regex: /(?:瑞典|SE(?![a-zA-Z])|Sweden)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f8-1f1ea.png?v8' },
    { name: 'AUS', regex: /(?:澳大利亚|澳洲|AU(?![a-zA-Z])|Australia)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1e6-1f1fa.png?v8' },
    { name: 'NGA', regex: /(?:尼日利亚|NG(?![a-zA-Z])|Nigeria)/i, flag: 'https://github.githubassets.com/images/icons/emoji/unicode/1f1f3-1f1ec.png?v8' }
  ];
  const countryGroups = [];
  const allMatchedNames = new Set();
  for (const item of countryDefs) {
    const matched = proxyNames.filter(name => item.regex.test(name));
    matched.forEach(n => allMatchedNames.add(n));
    countryGroups.push({
      name: item.name,
      type: 'select',
      proxies: matched.length > 0 ? matched : ['DIRECT'],
      icon: item.flag
    });
  }
  const othMatched = proxyNames.filter(name => !allMatchedNames.has(name));
  countryGroups.push({
    name: 'OTH',
    type: 'select',
    proxies: othMatched.length > 0 ? othMatched : ['DIRECT'],
    icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f3f4-2620.png?v8'
  });
  const defaultProxies = [
    'DIRECT',
    'ALL',
    'HKG', 'MAC', 'TWN', 'JPN', 'KOR',
    'SGP', 'MYS', 'THA', 'VNM', 'IDN', 'IND', 'ARE',
    'USA', 'CAN', 'MEX', 'BRA',
    'UKR', 'ROU', 'LTU', 'ITA', 'TUR', 'GBR', 'DEU', 'FRA', 'NLD', 'SWE',
    'AUS', 'NGA', 'OTH'
  ];
  const coreGroups = [
    {
      name: 'DEFAULT',
      type: 'select',
      proxies: defaultProxies,
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f680.png?v8'
    },
    {
      name: 'ALL',
      type: 'select',
      proxies: proxyNames.length > 0 ? proxyNames : ['DIRECT'],
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f30f.png?v8'
    },
    {
      name: 'STORE',
      type: 'select',
      proxies: ['HKG', 'DEFAULT', 'DIRECT'],
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f3ae.png?v8'
    },
    {
      name: 'WIKI',
      type: 'select',
      proxies: ['HKG', 'DEFAULT', 'DIRECT'],
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f4da.png?v8'
    },
    {
      name: 'PIKPAK',
      type: 'select',
      proxies: ['HKG', 'DEFAULT', 'DIRECT'],
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f5c3.png?v8'
    },
    {
      name: 'SRGB',
      type: 'select',
      proxies: ['USA', 'DEFAULT', 'DIRECT'],
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f4a1.png?v8'
    },
    {
      name: 'SLIP',
      type: 'select',
      proxies: ['DEFAULT', 'DIRECT'],
      icon: 'https://github.githubassets.com/images/icons/emoji/unicode/1f41f.png?v8'
    }
  ];
  config['proxy-groups'] = [
    coreGroups[0], // DEFAULT
    coreGroups[1], // ALL
    ...countryGroups,
    coreGroups[2], // STORE
    coreGroups[3], // WIKI
    coreGroups[4], // PIKPAK
    coreGroups[5], // SRGB
    coreGroups[6]  // SLIP
  ];
  return config;
}
