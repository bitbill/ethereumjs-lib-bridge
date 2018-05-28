# ethereumjs-lib-bridge

## 安装依赖
`npm install`

## 转译命令
`npm start`

## 函数调用格式
```
bridge.methodName('param1', 'param2')
```

## 公开的函数
名称 | 功能 | 参数 | 返回值
--- | --- | --- | ---
mnemonicToSeed | 助记词生成seed | mnemonic：助记词 | 助记词字符串，以空格隔开
seedToAddress | seed生成地址 | seed：buffer | buffer，不是hex字符串
seedHexToAddress | seed hex字符串生产地址 | seed：hex字符串 |
isValidAddress | 校验地址 | address：地址 | 字符串
isValidChecksumAddress | 校验地址 | address：地址 | 字符串
