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
mnemonicToSeed | 助记词生成seed | mnemonic: 助记词 | 助记词字符串，以空格隔开
seedToAddress | seed生成地址 | seed: buffer | buffer，不是hex字符串
seedHexToAddress | seed生成地址 | seedHex: hex字符串 | 地址
isValidAddress | 校验地址 | address: 地址 | 字符串
seedHexToPrivateHex | seed生成私钥 | seedHex: hex字符串 <br> path: 可选，默认eth地址路径 | Hexed-privateKey
generateMnemonicStore | 生成mnemonicStore | password: 密码 <br> mnemonic: 助记词 | mnemonicStore，类似于keystore
getMnemonicFromMnemonicStore | 生成助记词 | password: 密码 <br> mnemonicStoreContent: 类似于keystore内容 | 助记词
