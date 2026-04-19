(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),e.crossOrigin===`use-credentials`?t.credentials=`include`:e.crossOrigin===`anonymous`?t.credentials=`omit`:t.credentials=`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();function e(e){if(e<=0n)throw Error(`Modulus must be positive`)}function t(e,t){let n=e<0n?-e:e,r=t<0n?-t:t;for(;r!==0n;){let e=n%r;n=r,r=e}return n}function n(e,t){let n=e,r=t,i=1n,a=0n,o=0n,s=1n;for(;r!==0n;){let e=n/r;[n,r]=[r,n-e*r],[i,a]=[a,i-e*a],[o,s]=[s,o-e*s]}return{gcd:n<0n?-n:n,x:i,y:o}}function r(e,n){if(e===0n||n===0n)return 0n;let r=e/t(e,n)*n;return r<0n?-r:r}function i(t,n,r){if(e(r),n<0n)throw Error(`Exponent must be non-negative`);let i=1n,a=(t%r+r)%r,o=n;for(;o>0n;)(o&1n)==1n&&(i=i*a%r),a=a*a%r,o>>=1n;return i}function a(t,r){e(r);let{gcd:i,x:a}=n(t,r);if(i!==1n)throw Error(`Inverse does not exist for ${t} mod ${r}`);return(a%r+r)%r}function o(e){return e<=0n?0:e.toString(2).length}function s(e){let t=new Uint8Array(e);return crypto.getRandomValues(t),t}function c(e){let t=0n;for(let n of e)t=t<<8n|BigInt(n);return t}function l(e){if(e<=1n)throw Error(`max must be greater than 1`);let t=o(e-1n),n=Math.ceil(t/8),r=1n<<BigInt(t);for(;;){let t=c(s(n));if(!(t>=r)&&t>0n&&t<e)return t}}function u(e){if(e<=2n)throw Error(`N must be greater than 2`);for(;;){let n=l(e);if(t(n,e)===1n)return n}}function d(e,t=40){if(e<2n)return!1;for(let t of[2n,3n,5n,7n,11n,13n,17n,19n,23n,29n,31n,37n]){if(e===t)return!0;if(e%t===0n)return!1}let n=e-1n,r=0;for(;(n&1n)==0n;)n>>=1n,r+=1;for(let a=0;a<t;a+=1){let t=i(l(e-3n)+2n,n,e);if(t===1n||t===e-1n)continue;let a=!0;for(let n=1;n<r;n+=1)if(t=i(t,2n,e),t===e-1n){a=!1;break}if(a)return!1}return!0}function f(e){return e<=0n?0:e.toString(2).length}function p(e,t){let n=e%t;return n>=0n?n:n+t}function m(e){let t=1n<<BigInt(e),n=1n<<BigInt(e-1),r=l(t);return r|=n,r|=1n,r}async function h(e,t){let n=0;for(;;){n+=1,t?.(n);let r=m(e);if(d(r,40))return r;n%20==0&&await new Promise(e=>{setTimeout(e,0)})}}function g(e,t){let n=e-1n;if(n%t!==0n)throw Error(`Invalid L input: (x - 1) is not divisible by N`);return n/t}async function _(e,n){if(e<12||e%2!=0)throw Error(`bitLength must be an even number >= 12`);let i=e/2,o=0;n?.(`Searching for prime p (${i} bits)...`,5);let s=await h(i,e=>{o=e;let t=Math.min(35,5+Math.floor(Math.log2(e+1)*4));n?.(`Searching for prime p (${i} bits)... attempt ${e}`,t)});n?.(`Prime p found after ${o} attempts`,40);let c=0,l=s;for(;l===s;)n?.(`Searching for prime q (${i} bits)...`,45),l=await h(i,e=>{c=e;let t=Math.min(75,45+Math.floor(Math.log2(e+1)*4));n?.(`Searching for prime q (${i} bits)... attempt ${e}`,t)});n?.(`Prime q found after ${c} attempts`,80),n?.(`Computing N = p * q`,85);let u=s*l,d=u*u,p=u+1n;n?.(`Computing lambda = lcm(p-1, q-1)`,90);let m=r(s-1n,l-1n);if(n?.(`Computing mu = lambda^-1 mod N`,95),t(m,u)!==1n)throw Error(`Invalid key material: gcd(lambda, N) != 1`);let g=a(m,u);return n?.(`Keypair generated`,100),{publicKey:{N:u,g:p,N2:d,bitLength:f(u)},privateKey:{lambda:m,mu:g,p:s,q:l}}}function v(e,t){let{N:n,N2:r}=t;if(e<0n||e>=n)throw Error(`Message must be in [0, N-1]`);let a=u(n);return{ciphertext:(1n+e*n)%r*i(a,n,r)%r,r:a}}function y(e,t){let{publicKey:n,privateKey:r}=t,{N:a,N2:o}=n;if(e<0n||e>=o)throw Error(`Ciphertext must be in [0, N^2-1]`);return p(g(i(e,r.lambda,o),a)*r.mu,a)}function b(e,t,n){return p(e,n.N2)*p(t,n.N2)%n.N2}function x(e,t,n){let r=p(t,n.N),a=i(n.g,r,n.N2);return p(e,n.N2)*a%n.N2}function S(e,t,n){if(t<0n)throw Error(`Scalar must be non-negative`);return i(p(e,n.N2),t,n.N2)}function C(e,t){let n=i(u(t.N),t.N,t.N2);return p(e,t.N2)*n%t.N2}function w(e,t){let n=e.map((e,n)=>{if(e<0n||e>=t.N)throw Error(`Hospital count must be in [0, N-1]`);return{id:`Hospital ${String.fromCharCode(65+n)}`,privateCount:e,encryptedCount:v(e,t).ciphertext}});return{hospitals:n,encryptedTotal:n.reduce((e,n)=>b(e,n.encryptedCount,t),1n)}}function T(e,t){let n=e.map((e,n)=>{if(e!==0&&e!==1)throw Error(`Votes must be 0 or 1`);return{voterId:`Voter ${n+1}`,encryptedVote:v(BigInt(e),t).ciphertext}});return{encryptedVotes:n,encryptedTally:n.reduce((e,n)=>b(e,n.encryptedVote,t),1n)}}function E(e,t,n){if(e.length!==t.length)throw Error(`encryptedValues and weights must have the same length`);let r=1n;for(let i=0;i<e.length;i+=1){let a=t[i];if(a<0n)throw Error(`weights must be non-negative`);let o=S(e[i],a,n);r=b(r,o,n)}return r}var D=document.querySelector(`#app`);if(!D)throw Error(`Missing app root`);D.innerHTML=`
  <main class="shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">crypto-lab-paillier-gate</p>
        <h1>The Additive Homomorphic Cryptosystem</h1>
        <p class="subtitle">Sealed ballots can be counted without opening them. That is Paillier in one line: E(a) · E(b) = E(a+b).</p>
      </div>
      <button id="theme-toggle" class="theme-toggle" style="position: absolute; top: 0; right: 0"></button>
    </header>

    <section class="card" id="exhibit-1">
      <h2>Exhibit 1: The Paillier Cryptosystem</h2>
      <div class="row">
        <label>Key size
          <select id="key-size">
            <option value="12">TOY (12-bit)</option>
            <option value="1024">1024-bit</option>
            <option value="2048" selected>2048-bit production</option>
          </select>
        </label>
        <button id="generate-key">Generate Keypair</button>
      </div>
      <p id="toy-warning" class="warning hidden">TOY - NOT PRODUCTION SECURE</p>
      <pre id="key-progress" class="console">No key generated yet.</pre>
      <div class="grid two">
        <article>
          <h3>Public key</h3>
          <p id="public-key-text">N = ...<br/>g = N + 1</p>
        </article>
        <article>
          <h3>Private key</h3>
          <p id="private-key-text">██████████████████ [Show]</p>
          <button id="toggle-private" class="ghost">Show private key</button>
        </article>
      </div>

      <div class="grid three">
        <label>Message m
          <input id="message-input" type="number" value="42" min="0" />
        </label>
        <button id="encrypt-btn">Encrypt</button>
        <button id="encrypt-again-btn" class="ghost">Encrypt again</button>
      </div>
      <button id="decrypt-btn" class="ghost">Decrypt latest ciphertext</button>
      <pre id="enc-output" class="console">Waiting for encryption demo.</pre>
    </section>

    <section class="card" id="exhibit-2">
      <h2>Exhibit 2: Additive Homomorphism</h2>
      <div class="grid three">
        <label>m1<input id="homo-a" type="number" value="7" min="0"/></label>
        <label>m2<input id="homo-b" type="number" value="13" min="0"/></label>
        <button id="run-homomorphic">Run E(a) · E(b)</button>
      </div>
      <div class="grid three">
        <label>Encrypted m<input id="add-plain-m" type="number" value="100" min="0"/></label>
        <label>Public k<input id="add-plain-k" type="number" value="50" min="0"/></label>
        <button id="run-add-plain">Run c · g^k</button>
      </div>
      <div class="grid three">
        <label>Encrypted m<input id="scalar-m" type="number" value="6" min="0"/></label>
        <label>Scalar k<input id="scalar-k" type="number" value="7" min="0"/></label>
        <button id="run-scalar">Run c^k</button>
      </div>
      <pre id="homo-output" class="console">Generate a keypair first.</pre>
      <div class="cannot">
        <h3>What you cannot do</h3>
        <p>Paillier does not support ciphertext-by-ciphertext multiplication. For that, use FHE (BGV/BFV/CKKS) or MPC-based multiplication.</p>
      </div>
    </section>

    <section class="card" id="exhibit-3">
      <h2>Exhibit 3: Private Voting (10 voters)</h2>
      <label>Votes (comma-separated 0/1)
        <input id="votes-input" value="1,1,0,1,0,1,0,1,1,0" />
      </label>
      <div class="row">
        <button id="run-election">Simulate election tally</button>
        <label class="toggle"><input id="show-votes" type="checkbox"/> Show plaintext votes for demo verification</label>
      </div>
      <pre id="vote-output" class="console">No election run yet.</pre>
    </section>

    <section class="card" id="exhibit-4">
      <h2>Exhibit 4: Private Aggregation (5 hospitals)</h2>
      <label>Hospital counts (comma-separated)
        <input id="hospital-input" value="10,25,17,8,30" />
      </label>
      <button id="run-hospitals">Simulate private aggregation</button>
      <pre id="hospital-output" class="console">No aggregation run yet.</pre>
    </section>

    <section class="card" id="exhibit-5">
      <h2>Exhibit 5: Paillier vs Other Homomorphic Schemes</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Property</th><th>Paillier (1999)</th><th>ElGamal Exponential</th><th>BGV/BFV (FHE)</th><th>CKKS (FHE)</th></tr>
          </thead>
          <tbody>
            <tr><td>Homomorphic operations</td><td>Addition + scalar mul</td><td>Addition</td><td>Add + multiply (limited depth)</td><td>Add + multiply (approximate)</td></tr>
            <tr><td>Ciphertext expansion</td><td>2x (N to N^2)</td><td>2x</td><td>30-100x</td><td>30-100x</td></tr>
            <tr><td>Deployment difficulty</td><td class="highlight">Low</td><td>Low</td><td>High</td><td>High</td></tr>
            <tr><td>Post-quantum</td><td>No (factoring)</td><td>No (DLP)</td><td class="highlight">Yes</td><td class="highlight">Yes</td></tr>
            <tr><td>Best for</td><td class="highlight">Voting, counting, averaging</td><td>Voting variant</td><td>Complex integer circuits</td><td>Encrypted ML/statistics</td></tr>
          </tbody>
        </table>
      </div>
      <p class="links">Cross-links: crypto-lab-gg20-wallet | crypto-lab-elgamal-plain | crypto-lab-ckks-lab | crypto-lab-fhe-arena | crypto-lab-silent-tally | crypto-lab-blind-oracle</p>
    </section>
  </main>
`;var O=document.getElementById(`key-size`),k=document.getElementById(`generate-key`),A=document.getElementById(`toy-warning`),j=document.getElementById(`key-progress`),M=document.getElementById(`public-key-text`),N=document.getElementById(`private-key-text`),P=document.getElementById(`toggle-private`),F=document.getElementById(`message-input`),I=document.getElementById(`encrypt-btn`),L=document.getElementById(`encrypt-again-btn`),R=document.getElementById(`decrypt-btn`),z=document.getElementById(`enc-output`),B=document.getElementById(`homo-output`),V=document.getElementById(`vote-output`),H=document.getElementById(`hospital-output`),U=document.getElementById(`theme-toggle`),W=null,G=null,K=null,q=!1,J=(e,t=24)=>{let n=e.toString(16);if(n.length<=t)return n;let r=Math.floor(t/2),i=t-r;return`${n.slice(0,r)}...${n.slice(-i)}`},Y=(e,t)=>{let n=e.trim();if(!/^\d+$/.test(n))throw Error(`${t} must be a non-negative integer`);return BigInt(n)},X=()=>{if(!W)throw Error(`Generate a keypair first`);return W},Z=()=>{if(!W){M.innerHTML=`N = ...<br/>g = N + 1`,N.textContent=`██████████████████ [Show]`;return}let{publicKey:e,privateKey:t}=W;M.innerHTML=`N = 0x${J(e.N,36)} (${e.bitLength} bits)<br/>g = N + 1`,N.textContent=q?`lambda = 0x${J(t.lambda,36)}\nmu = 0x${J(t.mu,36)}`:`██████████████████ [Show]`},Q=e=>{let t=t=>{document.documentElement.setAttribute(`data-theme`,t),localStorage.setItem(`theme`,t),e.textContent=t===`dark`?`🌙`:`☀️`,e.setAttribute(`aria-label`,t===`dark`?`Switch to light mode`:`Switch to dark mode`)};t(document.documentElement.getAttribute(`data-theme`)===`light`?`light`:`dark`),e.addEventListener(`click`,()=>{t(document.documentElement.getAttribute(`data-theme`)===`light`?`dark`:`light`)})};P.addEventListener(`click`,()=>{q=!q,P.textContent=q?`Hide private key`:`Show private key`,Z()}),k.addEventListener(`click`,async()=>{let e=Number(O.value);A.classList.toggle(`hidden`,e!==12),k.disabled=!0,j.textContent=`Starting key generation...`;let t=performance.now();try{W=await _(e,(e,t)=>{j.textContent=`[${t}%] ${e}`});let n=((performance.now()-t)/1e3).toFixed(2);j.textContent+=`\nKeypair generated in ${n}s`,Z(),B.textContent=`Key ready. Run the homomorphic demonstrations.`}catch(e){j.textContent=`Key generation failed: ${e.message}`}finally{k.disabled=!1}});var $=()=>{let e=X(),t=Y(F.value,`Message`);if(t>=e.publicKey.N)throw Error(`Message must be less than N`);let{ciphertext:n,r}=v(t,e.publicKey);G=n,K=t,z.textContent=[`m = ${t.toString()}`,`r = 0x${J(r)}`,`c = g^m * r^N mod N^2 = 0x${J(n,40)}`,`Same message encrypted again should produce a different ciphertext.`].join(`
`)};I.addEventListener(`click`,()=>{try{$()}catch(e){z.textContent=`Encryption failed: ${e.message}`}}),L.addEventListener(`click`,()=>{try{$()}catch(e){z.textContent=`Encryption failed: ${e.message}`}}),R.addEventListener(`click`,()=>{try{let e=X();if(G===null)throw Error(`Encrypt a message first`);let t=y(G,e);z.textContent+=`\nDecrypt latest c -> m = ${t.toString()}${K===null?``:` (expected ${K.toString()})`}`}catch(e){z.textContent=`Decryption failed: ${e.message}`}});var ee=()=>{let e=X(),t=Y(document.getElementById(`homo-a`).value,`m1`),n=Y(document.getElementById(`homo-b`).value,`m2`),r=v(t,e.publicKey).ciphertext,i=v(n,e.publicKey).ciphertext,a=b(r,i,e.publicKey),o=y(a,e);B.textContent=[`c1 = E(${t.toString()}) = 0x${J(r)}`,`c2 = E(${n.toString()}) = 0x${J(i)}`,`c3 = c1 * c2 mod N^2 = 0x${J(a)}`,`decrypt(c3) = ${o.toString()} (expected ${(t+n)%e.publicKey.N})`].join(`
`)},te=()=>{let e=X(),t=Y(document.getElementById(`add-plain-m`).value,`Encrypted m`),n=Y(document.getElementById(`add-plain-k`).value,`Public k`),r=v(t,e.publicKey).ciphertext,i=x(r,n,e.publicKey),a=y(i,e);B.textContent=[`c = E(${t.toString()}) = 0x${J(r)}`,`c' = c * g^${n.toString()} mod N^2 = 0x${J(i)}`,`decrypt(c') = ${a.toString()} (expected ${(t+n)%e.publicKey.N})`].join(`
`)},ne=()=>{let e=X(),t=Y(document.getElementById(`scalar-m`).value,`Encrypted m`),n=Y(document.getElementById(`scalar-k`).value,`Scalar k`),r=v(t,e.publicKey).ciphertext,i=S(r,n,e.publicKey),a=y(i,e);B.textContent=[`c = E(${t.toString()}) = 0x${J(r)}`,`c' = c^${n.toString()} mod N^2 = 0x${J(i)}`,`decrypt(c') = ${a.toString()} (expected ${t*n%e.publicKey.N})`].join(`
`)};document.getElementById(`run-homomorphic`)?.addEventListener(`click`,()=>{try{ee()}catch(e){B.textContent=`Homomorphic addition failed: ${e.message}`}}),document.getElementById(`run-add-plain`)?.addEventListener(`click`,()=>{try{te()}catch(e){B.textContent=`Plaintext addition failed: ${e.message}`}}),document.getElementById(`run-scalar`)?.addEventListener(`click`,()=>{try{ne()}catch(e){B.textContent=`Scalar multiplication failed: ${e.message}`}}),document.getElementById(`run-election`)?.addEventListener(`click`,()=>{try{let e=X(),t=document.getElementById(`votes-input`).value.split(`,`).map(e=>Number(e.trim())),{encryptedVotes:n,encryptedTally:r}=T(t,e.publicKey),i=y(r,e),a=document.getElementById(`show-votes`).checked;V.textContent=`${n.map((e,n)=>{let r=a?` vote=${t[n]}`:``;return`${e.voterId}:${r} ct=0x${J(e.encryptedVote)}`}).join(`
`)}\n\nEncrypted tally = 0x${J(r)}\nDecrypted tally for candidate A = ${i.toString()}`}catch(e){V.textContent=`Election simulation failed: ${e.message}`}}),document.getElementById(`run-hospitals`)?.addEventListener(`click`,()=>{try{let e=X(),{hospitals:t,encryptedTotal:n}=w(document.getElementById(`hospital-input`).value.split(`,`).map(e=>Y(e,`Hospital count`)),e.publicKey),r=y(n,e),i=y(C(n,e.publicKey),e),a=y(E(t.map(e=>e.encryptedCount),[1n,1n,1n,1n,1n],e.publicKey),e);H.textContent=[...t.map(e=>`${e.id}: private=${e.privateCount.toString()} ct=0x${J(e.encryptedCount)}`),``,`Encrypted total = 0x${J(n)}`,`Decrypted total = ${r.toString()}`,`Rerandomized total decrypts to = ${i.toString()}`,`Weighted-sum check (all weights 1) = ${a.toString()}`].join(`
`)}catch(e){H.textContent=`Aggregation simulation failed: ${e.message}`}}),Q(U),Z();