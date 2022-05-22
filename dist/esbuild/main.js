(()=>{var H=Object.create;var T=Object.defineProperty;var V=Object.getOwnPropertyDescriptor;var M=Object.getOwnPropertyNames;var j=Object.getPrototypeOf,q=Object.prototype.hasOwnProperty;var y=(s=>typeof require!="undefined"?require:typeof Proxy!="undefined"?new Proxy(s,{get:(e,r)=>(typeof require!="undefined"?require:e)[r]}):s)(function(s){if(typeof require!="undefined")return require.apply(this,arguments);throw new Error('Dynamic require of "'+s+'" is not supported')});var $=(s,e,r,t)=>{if(e&&typeof e=="object"||typeof e=="function")for(let a of M(e))!q.call(s,a)&&a!==r&&T(s,a,{get:()=>e[a],enumerable:!(t=V(e,a))||t.enumerable});return s};var d=(s,e,r)=>(r=s!=null?H(j(s)):{},$(e||!s||!s.__esModule?T(r,"default",{value:s,enumerable:!0}):r,s));var c=(s,e,r)=>new Promise((t,a)=>{var i=h=>{try{n(r.next(h))}catch(f){a(f)}},o=h=>{try{n(r.throw(h))}catch(f){a(f)}},n=h=>h.done?t(h.value):Promise.resolve(h.value).then(i,o);n((r=r.apply(s,e)).next())});var _=d(y("atob")),F=d(y("web3")),U=y("js-base64"),N=d(y("eth2-keystore-js"));var k;try{window.crypto,k=y("bls-eth-wasm/browser")}catch(s){k=y("bls-eth-wasm")}var u=k;var S=class{constructor(){this.validatorShares=[]}static get DEFAULT_SHARES_NUMBER(){return 4}static get DEFAULT_THRESHOLD_NUMBER(){return 3}create(a){return c(this,arguments,function*(e,r=S.DEFAULT_SHARES_NUMBER,t=S.DEFAULT_THRESHOLD_NUMBER){return new Promise((i,o)=>{try{u.init(u.BLS12_381).then(()=>{let n=[],h=[];this.validatorPrivateKey=u.deserializeHexStrToSecretKey(e),this.validatorPublicKey=this.validatorPrivateKey.getPublicKey(),n.push(this.validatorPrivateKey),h.push(this.validatorPublicKey);for(let l=1;l<t;l+=1){let p=new u.SecretKey;p.setByCSPRNG(),n.push(p);let m=p.getPublicKey();h.push(m)}for(let l=1;l<=r;l+=1){let p=new u.Id;p.setInt(l);let m=new u.SecretKey;m.share(n,p);let R=new u.PublicKey;R.share(h,p),this.validatorShares.push({privateKey:`0x${m.serializeToHexStr()}`,publicKey:`0x${R.serializeToHexStr()}`,id:p})}let f={validatorPrivateKey:`0x${this.validatorPrivateKey.serializeToHexStr()}`,validatorPublicKey:`0x${this.validatorPublicKey.serializeToHexStr()}`,shares:this.validatorShares};i(f)})}catch(n){o(n)}})})}},b=S;var D=y("js-base64");var x;try{window.crypto,x=y("jsencrypt")}catch(s){x=y("node-jsencrypt")}var O=x;var g=class{constructor(e,r){this.RAW_OPERATOR_PUBLIC_KEY_SIGNATURE=RegExp(/------BEGIN RSA PUBLIC KEY-----/,"gmi");this.operators=e.map(t=>this.RAW_OPERATOR_PUBLIC_KEY_SIGNATURE.test(t)?t:(0,D.decode)(t)),this.shares=r}encrypt(){let e=[];return Object.keys(this.operators).forEach(r=>{let t=new O({});t.setPublicKey(this.operators[r]);let a=t.encrypt(this.shares[r].privateKey),i={operatorPublicKey:this.operators[r],privateKey:String(a),publicKey:this.shares[r].publicKey};return e.push(i),i}),e}};var P=class{constructor(){this.web3Instances={}}getWeb3(e=process.env.NODE_URL||""){return this.web3Instances[e]||(this.web3Instances[e]=new F.default(String(e||""))),this.web3Instances[e]}getPrivateKeyFromKeystoreData(e,r){return c(this,null,function*(){try{try{e=JSON.parse(e)}catch(a){}return yield new N.default(e).getPrivateKey(r).then(a=>a)}catch(t){return console.error(t),t}})}createThreshold(e){return c(this,null,function*(){try{return new b().create(e)}catch(r){return console.error(r),r}})}encryptShares(a,i){return c(this,arguments,function*(e,r,t=P.OPERATOR_FORMAT_BASE64){try{let o=e.map(n=>(n=(0,_.default)(n),t==P.OPERATOR_FORMAT_BASE64?String((0,U.encode)(n)):n));return new g(o,r).encrypt()}catch(o){return console.error(o),o}})}abiEncode(e,r){return e.map(t=>this.getWeb3().eth.abi.encodeParameter("string",Object(t)[r]))}buildPayload(e,r){return c(this,null,function*(){let t=yield this.createThreshold(e),a=this.abiEncode(r,"operatorPublicKey"),i=r.map(n=>n.publicKey),o=this.abiEncode(r,"privateKey");return[t.validatorPublicKey,a,i,o]})}},K=P;K.OPERATOR_FORMAT_BASE64="base64";var I=class extends K{buildPayloadV2(e,r,t,a){return c(this,null,function*(){let i=yield this.createThreshold(e),o=t.map(h=>h.publicKey),n=this.abiEncode(t,"privateKey");return[i.validatorPublicKey,`[${r.join(",")}]`,o,n,a]})}};var L=d(y("web3")),v=class{constructor(){this.contractAddress="";this.nodeUrl="";this.contracts={};this.web3Instances={}}getWeb3(e=process.env.NODE_URL||""){return this.web3Instances[e]||(this.web3Instances[e]=new L.default(String(e||""))),this.web3Instances[e]}getLiquidationCollateral(){return c(this,null,function*(){return this.getContract().methods.minimumBlocksBeforeLiquidation().call()})}getNetworkFee(){return c(this,null,function*(){return this.getContract().methods.networkFee().call()})}getContract(){return this.contracts[this.contractAddress]||(this.contracts[this.contractAddress]=this.getWeb3(this.nodeUrl)),this.contracts[this.contractAddress]}setContractAddress(e){this.contractAddress=e}setNodeUrl(e){this.nodeUrl=e}};v.BLOCKS_PER_YEAR=2398050;var A=d(y("crypto")),C=y("scrypt-js"),E=d(y("ethereumjs-wallet")),w=y("ethereumjs-util"),B=class{constructor(e){this.privateKey="";if(!e)throw new Error("Key store data should be JSON or string");if(this.keyStoreData=JSON.parse(String(e)),!this.keyStoreData.version)throw new Error("Invalid keystore file")}getPublicKey(){var e;if(this.keyStoreData)switch((e=this.keyStoreData.version)!=null?e:this.keyStoreData.Version){case 1:return this.keyStoreData.Address;case 3:return this.keyStoreData.id;case 4:return this.keyStoreData.pubkey}return""}getPrivateKey(e=""){return c(this,null,function*(){if(this.privateKey)return this.privateKey;switch(this.keyStoreData.version){case 1:this.wallet=yield E.default.fromV1(this.keyStoreData,e);break;case 3:this.wallet=yield E.default.fromV3(this.keyStoreData,e,!0);break;case 4:this.wallet=yield this.fromV4(this.keyStoreData,e);break}if(this.wallet&&(this.privateKey=this.wallet.getPrivateKey().toString("hex"),!this.privateKey))throw new Error("Invalid password");return this.privateKey})}fromV4(e,r){return c(this,null,function*(){let t=typeof e=="object"?e:JSON.parse(e);if(t.version!==4)throw new Error("Not a V4 wallet");let a,i;if(t.crypto.kdf.function==="scrypt")i=t.crypto.kdf.params,a=yield(0,C.scrypt)(Buffer.from(r),Buffer.from(i.salt,"hex"),i.n,i.r,i.p,i.dklen);else if(t.crypto.kdf.function==="pbkdf2"){if(i=t.crypto.kdf.params,i.prf!=="hmac-sha256")throw new Error("Unsupported parameters to PBKDF2");a=A.default.pbkdf2Sync(Buffer.from(r),Buffer.from(i.salt,"hex"),i.c,i.dklen,"sha256")}else throw new Error("Unsupported key derivation scheme");let o=Buffer.from(t.crypto.cipher.message,"hex"),n=Buffer.concat([Buffer.from(a.slice(16,32)),o]);if({keccak256:w.keccak256,sha256:w.sha256}[t.crypto.checksum.function](n).toString("hex")!==t.crypto.checksum.message)throw new Error("Invalid password");let p=A.default.createDecipheriv(t.crypto.cipher.function,a.slice(0,16),Buffer.from(t.crypto.cipher.params.iv,"hex")),m=this.runCipherBuffer(p,o);return new E.default(m)})}runCipherBuffer(e,r){return Buffer.concat([e.update(r),e.final()])}static toHexString(e){return Array.from(e,r=>`0${(r&255).toString(16)}`.slice(-2)).join("")}},W=B;})();
