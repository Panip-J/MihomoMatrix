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
    { name: 'HKG', regex: /(?:香港|HK(?![a-zA-Z])|HongKong|Hong Kong)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/hk.svg' },
    { name: 'MAC', regex: /(?:澳门|MO(?![a-zA-Z])|Macau|Macao)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/mo.svg' },
    { name: 'TWN', regex: /(?:台湾|TW(?![a-zA-Z])|Taiwan)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/tw.svg' },
    { name: 'JPN', regex: /(?:日本|JP(?![a-zA-Z])|Japan)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/jp.svg' },
    { name: 'KOR', regex: /(?:韩国|KR(?![a-zA-Z])|Korea)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/kr.svg' },
    { name: 'SGP', regex: /(?:新加坡|SG(?![a-zA-Z])|Singapore)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/sg.svg' },
    { name: 'MYS', regex: /(?:马来|MY(?![a-zA-Z])|Malaysia)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/my.svg' },
    { name: 'THA', regex: /(?:泰国|TH(?![a-zA-Z])|Thailand)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/th.svg' },
    { name: 'VNM', regex: /(?:越南|VN(?![a-zA-Z])|Vietnam)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/vn.svg' },
    { name: 'IDN', regex: /(?:印尼|印度尼西亚|ID(?![a-zA-Z])|Indonesia)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/id.svg' },
    { name: 'IND', regex: /(?:(?<!印)印度(?!尼西亚)|IN(?![a-zA-Z])|India)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/in.svg' },
    { name: 'ARE', regex: /(?:阿拉伯联合酋长国|阿联酋|迪拜|阿布扎比|AE(?![a-zA-Z])|UAE|United Arab Emirates)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/ae.svg' },
    { name: 'USA', regex: /(?:美国|US(?![a-zA-Z])|UnitedStates|United States)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/us.svg' },
    { name: 'CAN', regex: /(?:加拿大|CA(?![a-zA-Z])|Canada)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/ca.svg' },
    { name: 'MEX', regex: /(?:墨西哥|MX(?![a-zA-Z])|Mexico)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/mx.svg' },
    { name: 'BRA', regex: /(?:巴西|BR(?![a-zA-Z])|Brazil)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/br.svg' },
    { name: 'UKR', regex: /(?:乌克兰|UA(?![a-zA-Z])|Ukraine)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/ua.svg' },
    { name: 'ROU', regex: /(?:罗马尼亚|RO(?![a-zA-Z])|Romania)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/ro.svg' },
    { name: 'LTU', regex: /(?:立陶宛|LT(?![a-zA-Z])|Lithuania)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/lt.svg' },
    { name: 'ITA', regex: /(?:意大利|IT(?![a-zA-Z])|Italy)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/it.svg' },
    { name: 'TUR', regex: /(?:土耳其|TR(?![a-zA-Z])|Turkey)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/tr.svg' },
    { name: 'GBR', regex: /(?:英国|UK(?![a-zA-Z])|GreatBritain|UnitedKingdom)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/gb.svg' },
    { name: 'DEU', regex: /(?:德国|DE(?![a-zA-Z])|Germany)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/de.svg' },
    { name: 'FRA', regex: /(?:法国|FR(?![a-zA-Z])|France)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/fr.svg' },
    { name: 'NLD', regex: /(?:荷兰|NL(?![a-zA-Z])|Netherlands)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/nl.svg' },
    { name: 'SWE', regex: /(?:瑞典|SE(?![a-zA-Z])|Sweden)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/se.svg' },
    { name: 'AUS', regex: /(?:澳大利亚|澳洲|AU(?![a-zA-Z])|Australia)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/au.svg' },
    { name: 'NGA', regex: /(?:尼日利亚|NG(?![a-zA-Z])|Nigeria)/i, flag: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/ng.svg' }
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
    icon: 'https://cdn.jsdelivr.net/gh/hatscripts/circle-flags@gh-pages/flags/xx.svg'
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
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png'
    },
    {
      name: 'ALL',
      type: 'select',
      proxies: proxyNames.length > 0 ? proxyNames : ['DIRECT'],
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png'
    },
    {
      name: 'STORE',
      type: 'select',
      proxies: ['HKG', 'DEFAULT', 'DIRECT'],
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Steam.png'
    },
    {
      name: 'WIKI',
      type: 'select',
      proxies: ['HKG', 'DEFAULT', 'DIRECT'],
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Puzzle.png'
    },
    {
      name: 'PIKPAK',
      type: 'select',
      proxies: ['HKG', 'DEFAULT', 'DIRECT'],
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/iCloud.png'
    },
    {
      name: 'SRGB',
      type: 'select',
      proxies: ['USA', 'DEFAULT', 'DIRECT'],
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Rainbow.png'
    },
    {
      name: 'SLIP',
      type: 'select',
      proxies: ['DEFAULT', 'DIRECT'],
      icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Final.png'
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
