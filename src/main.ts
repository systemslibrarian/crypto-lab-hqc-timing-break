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

type KeySizePreset = 12 | 1024 | 2048

const app = document.querySelector<HTMLDivElement>('#app')

if (!app) {
  throw new Error('Missing app root')
}

app.innerHTML = `
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

const hexShort = (value: bigint, width = 24): string => {
  const hex = value.toString(16)
  if (hex.length <= width) {
    return hex
  }
  const head = Math.floor(width / 2)
  const tail = width - head
  return `${hex.slice(0, head)}...${hex.slice(-tail)}`
}

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
  publicKeyText.innerHTML = `N = 0x${hexShort(publicKey.N, 36)} (${publicKey.bitLength} bits)<br/>g = N + 1`
  privateKeyText.textContent = showPrivate
    ? `lambda = 0x${hexShort(privateKey.lambda, 36)}\nmu = 0x${hexShort(privateKey.mu, 36)}`
    : '██████████████████ [Show]'
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
  updateKeyPanels()
})

generateButton.addEventListener('click', async () => {
  const bitLength = Number(keySizeSelect.value) as KeySizePreset
  toyWarning.classList.toggle('hidden', bitLength !== 12)

  generateButton.disabled = true
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
  }
})

const runEncrypt = (): void => {
  const kp = requireKeyPair()
  const m = parseNonNegativeBigInt(messageInput.value, 'Message')
  if (m >= kp.publicKey.N) {
    throw new Error('Message must be less than N')
  }
  const { ciphertext, r } = encrypt(m, kp.publicKey)
  lastCiphertext = ciphertext
  lastMessage = m
  encOutput.textContent = [
    `m = ${m.toString()}`,
    `r = 0x${hexShort(r)}`,
    `c = g^m * r^N mod N^2 = 0x${hexShort(ciphertext, 40)}`,
    'Same message encrypted again should produce a different ciphertext.',
  ].join('\n')
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
    `c1 = E(${a.toString()}) = 0x${hexShort(c1)}`,
    `c2 = E(${b.toString()}) = 0x${hexShort(c2)}`,
    `c3 = c1 * c2 mod N^2 = 0x${hexShort(c3)}`,
    `decrypt(c3) = ${sum.toString()} (expected ${(a + b) % kp.publicKey.N})`,
  ].join('\n')
}

const runAddPlain = (): void => {
  const kp = requireKeyPair()
  const m = parseNonNegativeBigInt((document.getElementById('add-plain-m') as HTMLInputElement).value, 'Encrypted m')
  const k = parseNonNegativeBigInt((document.getElementById('add-plain-k') as HTMLInputElement).value, 'Public k')
  const c = encrypt(m, kp.publicKey).ciphertext
  const cPrime = addPlaintext(c, k, kp.publicKey)
  const result = decrypt(cPrime, kp)
  homoOutput.textContent = [
    `c = E(${m.toString()}) = 0x${hexShort(c)}`,
    `c' = c * g^${k.toString()} mod N^2 = 0x${hexShort(cPrime)}`,
    `decrypt(c') = ${result.toString()} (expected ${(m + k) % kp.publicKey.N})`,
  ].join('\n')
}

const runScalar = (): void => {
  const kp = requireKeyPair()
  const m = parseNonNegativeBigInt((document.getElementById('scalar-m') as HTMLInputElement).value, 'Encrypted m')
  const k = parseNonNegativeBigInt((document.getElementById('scalar-k') as HTMLInputElement).value, 'Scalar k')
  const c = encrypt(m, kp.publicKey).ciphertext
  const cPrime = multiplyByScalar(c, k, kp.publicKey)
  const result = decrypt(cPrime, kp)
  homoOutput.textContent = [
    `c = E(${m.toString()}) = 0x${hexShort(c)}`,
    `c' = c^${k.toString()} mod N^2 = 0x${hexShort(cPrime)}`,
    `decrypt(c') = ${result.toString()} (expected ${(m * k) % kp.publicKey.N})`,
  ].join('\n')
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
      return `${vote.voterId}:${plain} ct=0x${hexShort(vote.encryptedVote)}`
    })
    voteOutput.textContent = `${lines.join('\n')}\n\nEncrypted tally = 0x${hexShort(encryptedTally)}\nDecrypted tally for candidate A = ${tally.toString()}`
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

    hospitalOutput.textContent = [
      ...hospitals.map((h) => `${h.id}: private=${h.privateCount.toString()} ct=0x${hexShort(h.encryptedCount)}`),
      '',
      `Encrypted total = 0x${hexShort(encryptedTotal)}`,
      `Decrypted total = ${total.toString()}`,
      `Rerandomized total decrypts to = ${rerandTotal.toString()}`,
      `Weighted-sum check (all weights 1) = ${weightedTotal.toString()}`,
    ].join('\n')
  } catch (error) {
    hospitalOutput.textContent = `Aggregation simulation failed: ${(error as Error).message}`
  }
})

initThemeToggle(themeToggle)
updateKeyPanels()
