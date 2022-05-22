(()=>{var W=Object.create;var R=Object.defineProperty;var H=Object.getOwnPropertyDescriptor;var M=Object.getOwnPropertyNames;var V=Object.getPrototypeOf,j=Object.prototype.hasOwnProperty;var c=(s=>typeof require!="undefined"?require:typeof Proxy!="undefined"?new Proxy(s,{get:(e,r)=>(typeof require!="undefined"?require:e)[r]}):s)(function(s){if(typeof require!="undefined")return require.apply(this,arguments);throw new Error('Dynamic require of "'+s+'" is not supported')});var q=(s,e,r,t)=>{if(e&&typeof e=="object"||typeof e=="function")for(let a of M(e))!j.call(s,a)&&a!==r&&R(s,a,{get:()=>e[a],enumerable:!(t=H(e,a))||t.enumerable});return s};var d=(s,e,r)=>(r=s!=null?W(V(s)):{},q(e||!s||!s.__esModule?R(r,"default",{value:s,enumerable:!0}):r,s));var y=(s,e,r)=>new Promise((t,a)=>{var i=o=>{try{n(r.next(o))}catch(l){a(l)}},h=o=>{try{n(r.throw(o))}catch(l){a(l)}},n=o=>o.done?t(o.value):Promise.resolve(o.value).then(i,h);n((r=r.apply(s,e)).next())});var D=d(c("atob")),_=d(c("web3")),F=c("js-base64"),U=d(c("eth2-keystore-js"));var k;try{window.crypto,k=c("bls-eth-wasm/browser")}catch(s){k=c("bls-eth-wasm")}var u=k;var S=class{constructor(){this.validatorShares=[]}static get DEFAULT_SHARES_NUMBER(){return 4}static get DEFAULT_THRESHOLD_NUMBER(){return 3}create(a){return y(this,arguments,function*(e,r=S.DEFAULT_SHARES_NUMBER,t=S.DEFAULT_THRESHOLD_NUMBER){return new Promise((i,h)=>{try{u.init(u.BLS12_381).then(()=>{let n=[],o=[];this.validatorPrivateKey=u.deserializeHexStrToSecretKey(e),this.validatorPublicKey=this.validatorPrivateKey.getPublicKey(),n.push(this.validatorPrivateKey),o.push(this.validatorPublicKey);for(let f=1;f<t;f+=1){let p=new u.SecretKey;p.setByCSPRNG(),n.push(p);let m=p.getPublicKey();o.push(m)}for(let f=1;f<=r;f+=1){let p=new u.Id;p.setInt(f);let m=new u.SecretKey;m.share(n,p);let B=new u.PublicKey;B.share(o,p),this.validatorShares.push({privateKey:`0x${m.serializeToHexStr()}`,publicKey:`0x${B.serializeToHexStr()}`,id:p})}let l={validatorPrivateKey:`0x${this.validatorPrivateKey.serializeToHexStr()}`,validatorPublicKey:`0x${this.validatorPublicKey.serializeToHexStr()}`,shares:this.validatorShares};i(l)})}catch(n){h(n)}})})}},K=S;var O=c("js-base64");var x;try{window.crypto,x=c("jsencrypt").JSEncrypt}catch(s){x=c("node-jsencrypt")}var T=x;var g=class{constructor(e,r){this.RAW_OPERATOR_PUBLIC_KEY_SIGNATURE=RegExp(/------BEGIN RSA PUBLIC KEY-----/,"gmi");this.operators=e.map(t=>this.RAW_OPERATOR_PUBLIC_KEY_SIGNATURE.test(t)?t:(0,O.decode)(t)),this.shares=r}encrypt(){let e=[];return Object.keys(this.operators).forEach(r=>{let t=new T({});t.setPublicKey(this.operators[r]);let a=t.encrypt(this.shares[r].privateKey),i={operatorPublicKey:this.operators[r],privateKey:String(a),publicKey:this.shares[r].publicKey};return e.push(i),i}),e}};var v=class{constructor(){this.web3Instances={}}getWeb3(e=process.env.NODE_URL||""){return this.web3Instances[e]||(this.web3Instances[e]=new _.default(String(e||""))),this.web3Instances[e]}getPrivateKeyFromKeystoreData(e,r){return y(this,null,function*(){try{try{e=JSON.parse(e)}catch(a){}return yield new U.default(e).getPrivateKey(r).then(a=>a)}catch(t){return console.error(t),t}})}createThreshold(e){return y(this,null,function*(){try{return new K().create(e)}catch(r){return console.error(r),r}})}encryptShares(a,i){return y(this,arguments,function*(e,r,t=v.OPERATOR_FORMAT_BASE64){try{let h=e.map(n=>(n=(0,D.default)(n),t==v.OPERATOR_FORMAT_BASE64?String((0,F.encode)(n)):n));return new g(h,r).encrypt()}catch(h){return console.error(h),h}})}abiEncode(e,r){return e.map(t=>this.getWeb3().eth.abi.encodeParameter("string",Object(t)[r]))}buildPayload(e,r,t,a){return y(this,null,function*(){let i=yield this.createThreshold(e),h=t.map(o=>o.publicKey),n=this.abiEncode(t,"privateKey");return[i.validatorPublicKey,`[${r.join(",")}]`,h,n,a]})}},b=v;b.OPERATOR_FORMAT_BASE64="base64";var N=d(c("web3")),P=class{constructor(){this.contractAddress="";this.nodeUrl="";this.contracts={};this.web3Instances={}}getWeb3(e=process.env.NODE_URL||""){return this.web3Instances[e]||(this.web3Instances[e]=new N.default(String(e||""))),this.web3Instances[e]}getLiquidationCollateral(){return y(this,null,function*(){return this.getContract().methods.minimumBlocksBeforeLiquidation().call()})}getNetworkFee(){return y(this,null,function*(){return this.getContract().methods.networkFee().call()})}getContract(){return this.contracts[this.contractAddress]||(this.contracts[this.contractAddress]=this.getWeb3(this.nodeUrl)),this.contracts[this.contractAddress]}setContractAddress(e){this.contractAddress=e}setNodeUrl(e){this.nodeUrl=e}};P.BLOCKS_PER_YEAR=2398050;var I=d(c("crypto")),L=c("scrypt-js"),E=d(c("ethereumjs-wallet")),w=c("ethereumjs-util"),A=class{constructor(e){this.privateKey="";if(!e)throw new Error("Key store data should be JSON or string");if(this.keyStoreData=JSON.parse(String(e)),!this.keyStoreData.version)throw new Error("Invalid keystore file")}getPublicKey(){var e;if(this.keyStoreData)switch((e=this.keyStoreData.version)!=null?e:this.keyStoreData.Version){case 1:return this.keyStoreData.Address;case 3:return this.keyStoreData.id;case 4:return this.keyStoreData.pubkey}return""}getPrivateKey(e=""){return y(this,null,function*(){if(this.privateKey)return this.privateKey;switch(this.keyStoreData.version){case 1:this.wallet=yield E.default.fromV1(this.keyStoreData,e);break;case 3:this.wallet=yield E.default.fromV3(this.keyStoreData,e,!0);break;case 4:this.wallet=yield this.fromV4(this.keyStoreData,e);break}if(this.wallet&&(this.privateKey=this.wallet.getPrivateKey().toString("hex"),!this.privateKey))throw new Error("Invalid password");return this.privateKey})}fromV4(e,r){return y(this,null,function*(){let t=typeof e=="object"?e:JSON.parse(e);if(t.version!==4)throw new Error("Not a V4 wallet");let a,i;if(t.crypto.kdf.function==="scrypt")i=t.crypto.kdf.params,a=yield(0,L.scrypt)(Buffer.from(r),Buffer.from(i.salt,"hex"),i.n,i.r,i.p,i.dklen);else if(t.crypto.kdf.function==="pbkdf2"){if(i=t.crypto.kdf.params,i.prf!=="hmac-sha256")throw new Error("Unsupported parameters to PBKDF2");a=I.default.pbkdf2Sync(Buffer.from(r),Buffer.from(i.salt,"hex"),i.c,i.dklen,"sha256")}else throw new Error("Unsupported key derivation scheme");let h=Buffer.from(t.crypto.cipher.message,"hex"),n=Buffer.concat([Buffer.from(a.slice(16,32)),h]);if({keccak256:w.keccak256,sha256:w.sha256}[t.crypto.checksum.function](n).toString("hex")!==t.crypto.checksum.message)throw new Error("Invalid password");let p=I.default.createDecipheriv(t.crypto.cipher.function,a.slice(0,16),Buffer.from(t.crypto.cipher.params.iv,"hex")),m=this.runCipherBuffer(p,h);return new E.default(m)})}runCipherBuffer(e,r){return Buffer.concat([e.update(r),e.final()])}static toHexString(e){return Array.from(e,r=>`0${(r&255).toString(16)}`.slice(-2)).join("")}},C=A;})();
