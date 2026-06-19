import './style.css'
import {
  addCiphertexts,
  addPlaintext,
  decrypt,
  encrypt,
  generateKeyPair,
  multiplyByScalar,
  rerandomize,
  type PaillierKeyPair,
} from './paillier'
import {
  simulatePrivateAggregation,
  simulatePrivateElection,
  weightedSum,
} from './aggregation'
import { modPow } from './numbers'
import { proveBit, soundnessError, verifyBit } from './zkproof'

type KeySizePreset = 12 | 1024 | 2048

const app = document.querySelector<HTMLDivElement>('#app')

if (!app) {
  throw new Error('Missing app root')
}

app.innerHTML = `
  <main class="shell" id="main" tabindex="-1">
    <header class="topbar">
      <div class="topbar-text">
        <p class="eyebrow">crypto-lab-paillier-gate</p>
        <h1>The Additive Homomorphic Cryptosystem</h1>
        <p class="subtitle">Sealed ballots can be counted without opening them. That is Paillier in one line: E(a) · E(b) = E(a+b).</p>
      </div>
      <button id="theme-toggle" type="button" class="theme-toggle" aria-label="Switch color theme">🌙</button>
    </header>

    <section class="card idea" id="big-idea" aria-labelledby="big-idea-title">
      <h2 id="big-idea-title">The One Identity That Makes This Work</h2>
      <p class="lead">Paillier encrypts a number <var>m</var> as <code>E(m) = g<sup>m</sup> · r<sup>N</sup> mod N²</code>, where <var>g</var> = N + 1 and <var>r</var> is fresh randomness. Multiply two sealed ciphertexts and watch the hidden numbers add — without ever decrypting:</p>
      <div class="math" role="img" aria-label="Derivation: E(a) times E(b) equals g to the a times r-one to the N, times g to the b times r-two to the N, which equals g to the a plus b times the quantity r-one r-two to the N, which equals E of a plus b.">
        <div class="math-line">E(a) · E(b) = (g<sup>a</sup>·r₁<sup>N</sup>) · (g<sup>b</sup>·r₂<sup>N</sup>) <span class="mod">mod N²</span></div>
        <div class="math-line indent">= g<sup>a+b</sup> · (r₁r₂)<sup>N</sup> <span class="mod">mod N²</span> <span class="annot">← exponents on g add; the r-parts combine</span></div>
        <div class="math-line indent">= <strong>E(a + b)</strong> <span class="annot">← same shape as a fresh encryption of a + b</span></div>
      </div>
      <p>Multiplying ciphertexts <strong>adds</strong> the plaintexts. That single line is why a sealed ballot box can be tallied without opening a single ballot. Two free corollaries fall out of the same algebra:</p>
      <ul class="corollaries">
        <li><code>c · g<sup>k</sup> = E(m + k)</code> — fold in a <em>public</em> constant <var>k</var>.</li>
        <li><code>c<sup>k</sup> = E(k · m)</code> — scale by a <em>public</em> weight <var>k</var>.</li>
      </ul>
      <details class="why">
        <summary>Why does g = N + 1 make g<sup>m</sup> trivial?</summary>
        <p>By the binomial theorem, <code>(1 + N)<sup>m</sup> = 1 + mN + (terms with N² or higher)</code>. Every term past the second is a multiple of N², so modulo N² they vanish:</p>
        <p class="math-line"><code>g<sup>m</sup> = (N+1)<sup>m</sup> ≡ 1 + mN (mod N²)</code></p>
        <p>No exponentiation needed — just one multiply. It also makes decryption's <var>L</var> function clean, because <code>L(1 + mN) = ((1+mN) − 1) / N = m</code>.</p>
      </details>
    </section>

    <section class="card notation" id="notation" aria-labelledby="notation-title">
      <h2 id="notation-title">Notation Key</h2>
      <dl class="glossary">
        <div><dt><var>m</var></dt><dd>the secret message (a number to encrypt), with 0 ≤ m &lt; N</dd></div>
        <div><dt><var>p</var>, <var>q</var></dt><dd>two large secret primes</dd></div>
        <div><dt><var>N</var></dt><dd>the public modulus, N = p · q</dd></div>
        <div><dt><var>N²</var></dt><dd>ciphertexts live mod N² — twice the size of N</dd></div>
        <div><dt><var>g</var></dt><dd>public base, fixed at g = N + 1</dd></div>
        <div><dt><var>r</var></dt><dd>fresh random value per encryption (gives semantic security)</dd></div>
        <div><dt><var>c</var></dt><dd>a ciphertext, c = E(m)</dd></div>
        <div><dt><var>λ</var></dt><dd>private key, λ = lcm(p−1, q−1)</dd></div>
        <div><dt><var>μ</var></dt><dd>private key, μ = λ⁻¹ mod N</dd></div>
        <div><dt><var>L</var></dt><dd>helper for decryption, L(x) = (x − 1) / N</dd></div>
      </dl>
    </section>

    <section class="card" id="exhibit-1">
      <h2>Exhibit 1: The Paillier Cryptosystem</h2>
      <p class="exhibit-intro">Generate a keypair, then encrypt a number and decrypt it back. <strong>Tip:</strong> pick <strong>TOY (12-bit)</strong> to see every value in full decimal and a step-by-step trace you can check by hand.</p>
      <div class="row">
        <label>Key size
          <select id="key-size">
            <option value="12">TOY (12-bit)</option>
            <option value="1024">1024-bit</option>
            <option value="2048" selected>2048-bit production</option>
          </select>
        </label>
        <button id="generate-key" type="button">Generate Keypair</button>
      </div>
      <p id="toy-warning" class="warning hidden" role="alert">TOY - NOT PRODUCTION SECURE</p>
      <pre id="key-progress" class="console" role="status" aria-live="polite" aria-atomic="true" aria-busy="false">No key generated yet.</pre>
      <div class="grid two">
        <article>
          <h3>Public key</h3>
          <p id="public-key-text">N = ...<br/>g = N + 1</p>
        </article>
        <article>
          <h3>Private key</h3>
          <p id="private-key-text" aria-live="polite">██████████████████ [Show]</p>
          <button id="toggle-private" type="button" class="ghost" aria-expanded="false">Show private key</button>
        </article>
      </div>

      <div class="grid three">
        <label>Message m
          <input id="message-input" type="number" value="42" min="0" />
        </label>
        <button id="encrypt-btn" type="button">Encrypt</button>
        <button id="encrypt-again-btn" type="button" class="ghost">Encrypt again</button>
      </div>
      <button id="decrypt-btn" type="button" class="ghost">Decrypt latest ciphertext</button>
      <pre id="enc-output" class="console" role="status" aria-live="polite" aria-atomic="true">Waiting for encryption demo.</pre>
      <details class="why">
        <summary>Why does encrypting 42 twice give two different ciphertexts?</summary>
        <p>Because of the fresh random <var>r</var> in <code>c = g<sup>m</sup>·r<sup>N</sup> mod N²</code>. Click <em>Encrypt again</em>: the two ciphertexts look completely unrelated, yet both decrypt to the same <var>m</var>. This is <strong>semantic security</strong> — an attacker who sees a ciphertext learns nothing, not even whether two ciphertexts hide the same value.</p>
        <p>Decryption peels off the randomness with the private key: <code>m = L(c<sup>λ</sup> mod N²) · μ mod N</code>, where raising to <var>λ</var> kills the r<sup>N</sup> term (Carmichael's theorem) and <var>L</var> extracts <var>m</var>.</p>
      </details>
    </section>

    <section class="card" id="exhibit-2">
      <h2>Exhibit 2: Additive Homomorphism</h2>
      <p class="exhibit-intro">The three operations from <a href="#big-idea">The Big Idea</a>, run live. Each computes a result purely from ciphertexts and <em>public</em> values, then decrypts only at the end to prove the math held.</p>
      <ul class="op-legend">
        <li><code>E(a)·E(b)</code> → adds two <em>secret</em> numbers</li>
        <li><code>c·g<sup>k</sup></code> → adds a <em>public</em> number k</li>
        <li><code>c<sup>k</sup></code> → multiplies by a <em>public</em> scalar k</li>
      </ul>
      <div class="grid three">
        <label>m1<input id="homo-a" type="number" value="7" min="0"/></label>
        <label>m2<input id="homo-b" type="number" value="13" min="0"/></label>
        <button id="run-homomorphic" type="button">Run E(a) · E(b)</button>
      </div>
      <div class="grid three">
        <label>Encrypted m<input id="add-plain-m" type="number" value="100" min="0"/></label>
        <label>Public k<input id="add-plain-k" type="number" value="50" min="0"/></label>
        <button id="run-add-plain" type="button">Run c · g^k</button>
      </div>
      <div class="grid three">
        <label>Encrypted m<input id="scalar-m" type="number" value="6" min="0"/></label>
        <label>Scalar k<input id="scalar-k" type="number" value="7" min="0"/></label>
        <button id="run-scalar" type="button">Run c^k</button>
      </div>
      <pre id="homo-output" class="console" role="status" aria-live="polite" aria-atomic="true">Generate a keypair first.</pre>
      <div class="cannot">
        <h3>What you cannot do</h3>
        <p><strong>No ciphertext × ciphertext.</strong> You can multiply a ciphertext by a <em>public</em> scalar, but not two ciphertexts together to multiply their secrets. For that you need FHE (BGV/BFV/CKKS) or MPC.</p>
        <p><strong>Sums wrap mod N.</strong> Homomorphic addition is addition modulo N. With a 2048-bit N that is astronomically large, so real tallies never overflow — but it is why the scheme is only meant for small numeric values, not bulk data.</p>
      </div>
    </section>

    <section class="card" id="exhibit-3">
      <h2>Exhibit 3: Private Voting (10 voters)</h2>
      <p class="exhibit-intro">Each voter encrypts a 0 or 1. Multiplying all ciphertexts together produces <code>E(v₁)·E(v₂)·…·E(v₁₀) = E(v₁+…+v₁₀)</code> — the encrypted tally. Only that single total is decrypted; no individual ballot is ever opened.</p>
      <label>Votes (comma-separated 0/1)
        <input id="votes-input" value="1,1,0,1,0,1,0,1,1,0" />
      </label>
      <div class="row">
        <button id="run-election" type="button">Simulate election tally</button>
        <label class="toggle"><input id="show-votes" type="checkbox"/> Show plaintext votes for demo verification</label>
      </div>
      <pre id="vote-output" class="console" role="status" aria-live="polite" aria-atomic="true">No election run yet.</pre>
    </section>

    <section class="card" id="exhibit-zk">
      <h2>Exhibit 4: Zero-Knowledge Ballot Validity</h2>
      <p class="exhibit-intro">Homomorphic tallying assumes every ballot is a 0 or a 1 — but nothing so far <em>forces</em> that. A cheater could encrypt 1000 and swing the election. Here each voter attaches a <strong>zero-knowledge proof</strong> that their ciphertext encrypts 0 or 1 — convincing the tallier without revealing the vote. Enter <strong>1</strong> for an honest ballot, or something like <strong>5</strong> to watch the proof get rejected.</p>
      <div class="grid three">
        <label>Ballot value<input id="zk-value" type="number" value="1" min="0"/></label>
        <button id="run-zk" type="button">Prove ballot is 0 or 1, then verify</button>
      </div>
      <pre id="zk-output" class="console" role="status" aria-live="polite" aria-atomic="true">Generate a keypair first.</pre>
      <details class="why">
        <summary>How can a proof reveal nothing yet still convince?</summary>
        <p>The proof is an <strong>OR of two Σ-protocols</strong> (Cramer–Damgård–Schoenmakers). To prove "the plaintext is 0 <em>or</em> 1", the voter runs the branch that is actually true honestly and <em>simulates</em> the false branch — picking that branch's challenge and response first and working backwards. A verifier sees two perfectly valid-looking branches and cannot tell which was real, so it learns nothing beyond "this is a bit." Fiat–Shamir (a SHA-256 hash of the transcript) replaces the verifier's coin flip, making the proof a single non-interactive object.</p>
        <p>Soundness: if the ciphertext encrypts anything other than 0 or 1, <em>neither</em> branch has a valid witness, so no transcript can satisfy both checks for a hash-chosen challenge — exactly why the cheating ballot above fails.</p>
      </details>
    </section>

    <section class="card" id="exhibit-4">
      <h2>Exhibit 5: Private Aggregation (5 hospitals)</h2>
      <p class="exhibit-intro">Five hospitals each encrypt a case count locally and share only ciphertexts. The combined total is computed under encryption. This run also <em>re-randomizes</em> the total (a different-looking ciphertext that decrypts to the same value — useful for unlinkability) and verifies a weighted sum.</p>
      <label>Hospital counts (comma-separated)
        <input id="hospital-input" value="10,25,17,8,30" />
      </label>
      <button id="run-hospitals" type="button">Simulate private aggregation</button>
      <pre id="hospital-output" class="console" role="status" aria-live="polite" aria-atomic="true">No aggregation run yet.</pre>
    </section>

    <section class="card" id="exhibit-5">
      <h2>Exhibit 6: Paillier vs Other Homomorphic Schemes</h2>
      <div class="table-wrap">
        <table>
          <caption>Comparison of Paillier and other homomorphic encryption schemes</caption>
          <thead>
            <tr><th scope="col">Property</th><th scope="col">Paillier (1999)</th><th scope="col">ElGamal Exponential</th><th scope="col">BGV/BFV (FHE)</th><th scope="col">CKKS (FHE)</th></tr>
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
`

const keySizeSelect = document.getElementById('key-size') as HTMLSelectElement
const generateButton = document.getElementById('generate-key') as HTMLButtonElement
const toyWarning = document.getElementById('toy-warning') as HTMLParagraphElement
const keyProgress = document.getElementById('key-progress') as HTMLPreElement
const publicKeyText = document.getElementById('public-key-text') as HTMLParagraphElement
const privateKeyText = document.getElementById('private-key-text') as HTMLParagraphElement
const togglePrivateBtn = document.getElementById('toggle-private') as HTMLButtonElement
const messageInput = document.getElementById('message-input') as HTMLInputElement
const encryptBtn = document.getElementById('encrypt-btn') as HTMLButtonElement
const encryptAgainBtn = document.getElementById('encrypt-again-btn') as HTMLButtonElement
const decryptBtn = document.getElementById('decrypt-btn') as HTMLButtonElement
const encOutput = document.getElementById('enc-output') as HTMLPreElement
const homoOutput = document.getElementById('homo-output') as HTMLPreElement
const voteOutput = document.getElementById('vote-output') as HTMLPreElement
const hospitalOutput = document.getElementById('hospital-output') as HTMLPreElement
const themeToggle = document.getElementById('theme-toggle') as HTMLButtonElement

let currentKeyPair: PaillierKeyPair | null = null
let lastCiphertext: bigint | null = null
let lastMessage: bigint | null = null
let showPrivate = false
let toyMode = false

const hexShort = (value: bigint, width = 24): string => {
  const hex = value.toString(16)
  if (hex.length <= width) {
    return hex
  }
  const head = Math.floor(width / 2)
  const tail = width - head
  return `${hex.slice(0, head)}...${hex.slice(-tail)}`
}

// In TOY mode the numbers are tiny, so show them in full so a learner can
// verify the arithmetic by hand. Otherwise show a truncated hex digest.
const fmt = (value: bigint, width = 24): string =>
  toyMode ? value.toString() : `0x${hexShort(value, width)}`

const parseNonNegativeBigInt = (value: string, field: string): bigint => {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${field} must be a non-negative integer`)
  }
  return BigInt(trimmed)
}

const requireKeyPair = (): PaillierKeyPair => {
  if (!currentKeyPair) {
    throw new Error('Generate a keypair first')
  }
  return currentKeyPair
}

const updateKeyPanels = (): void => {
  if (!currentKeyPair) {
    publicKeyText.innerHTML = 'N = ...<br/>g = N + 1'
    privateKeyText.textContent = '██████████████████ [Show]'
    return
  }
  const { publicKey, privateKey } = currentKeyPair
  publicKeyText.innerHTML = toyMode
    ? `N = ${publicKey.N} (${publicKey.bitLength} bits)<br/>g = N + 1 = ${publicKey.g}`
    : `N = 0x${hexShort(publicKey.N, 36)} (${publicKey.bitLength} bits)<br/>g = N + 1`
  if (!showPrivate) {
    privateKeyText.textContent = '██████████████████ [Show]'
  } else if (toyMode) {
    privateKeyText.textContent = [
      `p = ${privateKey.p}   (secret prime)`,
      `q = ${privateKey.q}   (secret prime)`,
      `N = p · q = ${publicKey.N}`,
      `λ = lcm(p−1, q−1) = ${privateKey.lambda}`,
      `μ = λ⁻¹ mod N = ${privateKey.mu}`,
    ].join('\n')
  } else {
    privateKeyText.textContent = `lambda = 0x${hexShort(privateKey.lambda, 36)}\nmu = 0x${hexShort(privateKey.mu, 36)}`
  }
}

const initThemeToggle = (button: HTMLButtonElement): void => {
  const apply = (theme: 'dark' | 'light') => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
    button.textContent = theme === 'dark' ? '🌙' : '☀️'
    button.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
    )
  }

  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'
  apply(current)

  button.addEventListener('click', () => {
    const next =
      document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light'
    apply(next)
  })
}

togglePrivateBtn.addEventListener('click', () => {
  showPrivate = !showPrivate
  togglePrivateBtn.textContent = showPrivate ? 'Hide private key' : 'Show private key'
  togglePrivateBtn.setAttribute('aria-expanded', String(showPrivate))
  updateKeyPanels()
})

generateButton.addEventListener('click', async () => {
  const bitLength = Number(keySizeSelect.value) as KeySizePreset
  toyMode = bitLength <= 16
  toyWarning.classList.toggle('hidden', bitLength !== 12)

  generateButton.disabled = true
  keyProgress.setAttribute('aria-busy', 'true')
  keyProgress.textContent = 'Starting key generation...'
  const start = performance.now()

  try {
    currentKeyPair = await generateKeyPair(bitLength, (stage, percent) => {
      keyProgress.textContent = `[${percent}%] ${stage}`
    })
    const elapsed = ((performance.now() - start) / 1000).toFixed(2)
    keyProgress.textContent += `\nKeypair generated in ${elapsed}s`
    updateKeyPanels()
    homoOutput.textContent = 'Key ready. Run the homomorphic demonstrations.'
  } catch (error) {
    keyProgress.textContent = `Key generation failed: ${(error as Error).message}`
  } finally {
    generateButton.disabled = false
    keyProgress.setAttribute('aria-busy', 'false')
  }
})

const runEncrypt = (): void => {
  const kp = requireKeyPair()
  const m = parseNonNegativeBigInt(messageInput.value, 'Message')
  if (m >= kp.publicKey.N) {
    throw new Error('Message must be less than N')
  }
  const { N, N2, g } = kp.publicKey
  const { ciphertext, r } = encrypt(m, kp.publicKey)
  lastCiphertext = ciphertext
  lastMessage = m

  const lines: string[] = [`m = ${m.toString()}`]
  if (toyMode) {
    const gm = (1n + m * N) % N2
    const rN = modPow(r, N, N2)
    lines.push(
      `g = N + 1 = ${g}`,
      `r = ${r}   (fresh random, gcd(r, N) = 1)`,
      `g^m mod N² = 1 + m·N = ${gm}`,
      `r^N mod N² = ${rN}`,
      `c = g^m · r^N mod N² = ${gm} · ${rN} mod ${N2}`,
      `c = ${ciphertext}`,
      '↑ one multiply and one mod — verify it on a calculator.',
    )
  } else {
    lines.push(
      `r = 0x${hexShort(r)}`,
      `c = g^m · r^N mod N² = 0x${hexShort(ciphertext, 40)}`,
    )
  }
  lines.push('Click "Encrypt again": same m, different c (fresh r).')
  encOutput.textContent = lines.join('\n')
}

encryptBtn.addEventListener('click', () => {
  try {
    runEncrypt()
  } catch (error) {
    encOutput.textContent = `Encryption failed: ${(error as Error).message}`
  }
})

encryptAgainBtn.addEventListener('click', () => {
  try {
    runEncrypt()
  } catch (error) {
    encOutput.textContent = `Encryption failed: ${(error as Error).message}`
  }
})

decryptBtn.addEventListener('click', () => {
  try {
    const kp = requireKeyPair()
    if (lastCiphertext === null) {
      throw new Error('Encrypt a message first')
    }
    const m = decrypt(lastCiphertext, kp)
    encOutput.textContent += `\nDecrypt latest c -> m = ${m.toString()}${lastMessage !== null ? ` (expected ${lastMessage.toString()})` : ''}`
  } catch (error) {
    encOutput.textContent = `Decryption failed: ${(error as Error).message}`
  }
})

const runHomomorphicAdd = (): void => {
  const kp = requireKeyPair()
  const a = parseNonNegativeBigInt((document.getElementById('homo-a') as HTMLInputElement).value, 'm1')
  const b = parseNonNegativeBigInt((document.getElementById('homo-b') as HTMLInputElement).value, 'm2')
  const c1 = encrypt(a, kp.publicKey).ciphertext
  const c2 = encrypt(b, kp.publicKey).ciphertext
  const c3 = addCiphertexts(c1, c2, kp.publicKey)
  const sum = decrypt(c3, kp)
  homoOutput.textContent = [
    `c1 = E(${a.toString()}) = ${fmt(c1)}`,
    `c2 = E(${b.toString()}) = ${fmt(c2)}`,
    `c3 = c1 · c2 mod N² = ${fmt(c3)}`,
    `decrypt(c3) = ${sum.toString()}  (expected ${(a + b) % kp.publicKey.N})`,
    sum === (a + b) % kp.publicKey.N ? '✓ multiplying ciphertexts added the secrets.' : '',
  ].filter(Boolean).join('\n')
}

const runAddPlain = (): void => {
  const kp = requireKeyPair()
  const m = parseNonNegativeBigInt((document.getElementById('add-plain-m') as HTMLInputElement).value, 'Encrypted m')
  const k = parseNonNegativeBigInt((document.getElementById('add-plain-k') as HTMLInputElement).value, 'Public k')
  const c = encrypt(m, kp.publicKey).ciphertext
  const cPrime = addPlaintext(c, k, kp.publicKey)
  const result = decrypt(cPrime, kp)
  homoOutput.textContent = [
    `c = E(${m.toString()}) = ${fmt(c)}`,
    `c' = c · g^${k.toString()} mod N² = ${fmt(cPrime)}`,
    `decrypt(c') = ${result.toString()}  (expected ${(m + k) % kp.publicKey.N})`,
    result === (m + k) % kp.publicKey.N ? '✓ folded in a public constant without decrypting.' : '',
  ].filter(Boolean).join('\n')
}

const runScalar = (): void => {
  const kp = requireKeyPair()
  const m = parseNonNegativeBigInt((document.getElementById('scalar-m') as HTMLInputElement).value, 'Encrypted m')
  const k = parseNonNegativeBigInt((document.getElementById('scalar-k') as HTMLInputElement).value, 'Scalar k')
  const c = encrypt(m, kp.publicKey).ciphertext
  const cPrime = multiplyByScalar(c, k, kp.publicKey)
  const result = decrypt(cPrime, kp)
  homoOutput.textContent = [
    `c = E(${m.toString()}) = ${fmt(c)}`,
    `c' = c^${k.toString()} mod N² = ${fmt(cPrime)}`,
    `decrypt(c') = ${result.toString()}  (expected ${(m * k) % kp.publicKey.N})`,
    result === (m * k) % kp.publicKey.N ? '✓ scaled the secret by a public weight.' : '',
  ].filter(Boolean).join('\n')
}

document.getElementById('run-homomorphic')?.addEventListener('click', () => {
  try {
    runHomomorphicAdd()
  } catch (error) {
    homoOutput.textContent = `Homomorphic addition failed: ${(error as Error).message}`
  }
})

document.getElementById('run-add-plain')?.addEventListener('click', () => {
  try {
    runAddPlain()
  } catch (error) {
    homoOutput.textContent = `Plaintext addition failed: ${(error as Error).message}`
  }
})

document.getElementById('run-scalar')?.addEventListener('click', () => {
  try {
    runScalar()
  } catch (error) {
    homoOutput.textContent = `Scalar multiplication failed: ${(error as Error).message}`
  }
})

document.getElementById('run-election')?.addEventListener('click', () => {
  try {
    const kp = requireKeyPair()
    const votesRaw = (document.getElementById('votes-input') as HTMLInputElement).value
      .split(',')
      .map((v) => Number(v.trim()))
    const { encryptedVotes, encryptedTally } = simulatePrivateElection(votesRaw, kp.publicKey)
    const tally = decrypt(encryptedTally, kp)
    const showVotes = (document.getElementById('show-votes') as HTMLInputElement).checked
    const lines = encryptedVotes.map((vote, index) => {
      const plain = showVotes ? ` vote=${votesRaw[index]}` : ''
      return `${vote.voterId}:${plain} ct=${fmt(vote.encryptedVote)}`
    })
    const expected = votesRaw.reduce((sum, v) => sum + v, 0)
    voteOutput.textContent = `${lines.join('\n')}\n\nEncrypted tally = ${fmt(encryptedTally)}\nDecrypted tally = ${tally.toString()} of ${votesRaw.length} votes  (expected ${expected})\nEvery ciphertext above stayed sealed — only the total was opened.`
  } catch (error) {
    voteOutput.textContent = `Election simulation failed: ${(error as Error).message}`
  }
})

document.getElementById('run-hospitals')?.addEventListener('click', () => {
  try {
    const kp = requireKeyPair()
    const counts = (document.getElementById('hospital-input') as HTMLInputElement).value
      .split(',')
      .map((v) => parseNonNegativeBigInt(v, 'Hospital count'))
    const { hospitals, encryptedTotal } = simulatePrivateAggregation(counts, kp.publicKey)
    const total = decrypt(encryptedTotal, kp)
    const rerand = rerandomize(encryptedTotal, kp.publicKey)
    const rerandTotal = decrypt(rerand, kp)
    const weighted = weightedSum(
      hospitals.map((h) => h.encryptedCount),
      [1n, 1n, 1n, 1n, 1n],
      kp.publicKey,
    )
    const weightedTotal = decrypt(weighted, kp)

    const expectedTotal = counts.reduce((sum, c) => sum + c, 0n)
    hospitalOutput.textContent = [
      ...hospitals.map((h) => `${h.id}: private=${h.privateCount.toString()} ct=${fmt(h.encryptedCount)}`),
      '',
      `Encrypted total = ${fmt(encryptedTotal)}`,
      `Decrypted total = ${total.toString()}  (expected ${expectedTotal})`,
      `Re-randomized total = ${fmt(rerand)}`,
      `  ↳ decrypts to ${rerandTotal.toString()} — different ciphertext, same value`,
      `Weighted-sum check (all weights 1) = ${weightedTotal.toString()}`,
    ].join('\n')
  } catch (error) {
    hospitalOutput.textContent = `Aggregation simulation failed: ${(error as Error).message}`
  }
})

document.getElementById('run-zk')?.addEventListener('click', async () => {
  const zkOutput = document.getElementById('zk-output') as HTMLPreElement
  const btn = document.getElementById('run-zk') as HTMLButtonElement
  try {
    const kp = requireKeyPair()
    const v = parseNonNegativeBigInt(
      (document.getElementById('zk-value') as HTMLInputElement).value,
      'Ballot value',
    )
    if (v >= kp.publicKey.N) {
      throw new Error('Ballot value must be less than N')
    }
    btn.disabled = true
    zkOutput.setAttribute('aria-busy', 'true')
    zkOutput.textContent = 'Encrypting ballot and building zero-knowledge proof...'

    const { ciphertext, r } = encrypt(v, kp.publicKey)
    const realBranch: 0 | 1 = v === 0n ? 0 : 1
    const proof = await proveBit(realBranch, ciphertext, r, kp.publicKey)
    const valid = await verifyBit(proof, ciphertext, kp.publicKey)
    const honest = v === 0n || v === 1n
    const { oneIn } = soundnessError(kp.publicKey)

    const lines = [
      `Claim: this ciphertext encrypts 0 or 1.   (actual value entered: ${v})`,
      `c = E(${v}) = ${fmt(ciphertext)}`,
      '',
      'Proof transcript — commitments a, split challenges e, responses z:',
      `  a0 = ${fmt(proof.a0)}`,
      `  a1 = ${fmt(proof.a1)}`,
      `  e0 = ${fmt(proof.e0)}    e1 = ${fmt(proof.e1)}`,
      `  z0 = ${fmt(proof.z0)}`,
      `  z1 = ${fmt(proof.z1)}`,
      '',
      valid
        ? 'Verifier: ✓ ACCEPT — provably a 0 or 1, without revealing which.'
        : 'Verifier: ✗ REJECT — this is not a valid 0/1 ballot.',
    ]
    if (honest) {
      lines.push('A real tally would count this ballot; the vote itself stays hidden.')
    } else if (!valid) {
      lines.push(`${v} is not a bit, so neither proof branch holds — ballot stuffing is caught.`)
    } else {
      lines.push(`${v} is not a bit, yet it slipped through — see the soundness note below.`)
    }
    lines.push(
      '',
      `Soundness: a cheater succeeds with probability ≈ 1 in ${oneIn}.`,
      toyMode
        ? 'TOY keys make that gap visible — try a non-bit a few times. Real 2048-bit keys push it to ~1 in 2^256 (never).'
        : 'With this key that is astronomically small — cheating is infeasible.',
    )
    zkOutput.textContent = lines.join('\n')
  } catch (error) {
    zkOutput.textContent = `Proof failed: ${(error as Error).message}`
  } finally {
    btn.disabled = false
    zkOutput.setAttribute('aria-busy', 'false')
  }
})

initThemeToggle(themeToggle)
updateKeyPanels()
