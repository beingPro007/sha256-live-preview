/* global BigInt */

import React, { useState } from "react";

const SHA256Visualizer = () => {
  const [input, setInput] = useState("");
  const [originalBinary, setOriginalBinary] = useState("");
  const [paddedMessage, setPaddedMessage] = useState("");
  const [messageSchedules, setMessageSchedules] = useState([]); // [{ blockIndex, schedule }]
  const [compressSteps, setCompressSteps] = useState([]); // [{ blockIndex, steps }]
  const [updatedHashes, setUpdatedHashes] = useState([]); // [{ blockIndex, registers: [H0...H7] }]
  const [finalHash, setFinalHash] = useState("");

  // SHA-256 Constants (all 64 values)
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  const initialHash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ];

  // Helper functions
  const rightRotate = (value, amount) =>
    (value >>> amount) | (value << (32 - amount));

  const toBinary = (str) =>
    str
      .split("")
      .map((char) => char.charCodeAt(0).toString(2).padStart(8, "0"))
      .join("");

  const preprocessMessage = (message) => {
    let binary = toBinary(message);
    const originalLength = binary.length;
    binary += "1"; // Append a single '1'
    while (binary.length % 512 !== 448) {
      binary += "0"; // Pad with zeros until length ≡ 448 mod 512
    }
    // Append original length as a 64-bit big-endian integer
    binary += BigInt(originalLength).toString(2).padStart(64, "0");
    return binary;
  };

  const createMessageSchedule = (block) => {
    const W = new Array(64);
    for (let i = 0; i < 16; i++) {
      W[i] = parseInt(block.slice(i * 32, (i + 1) * 32), 2);
    }
    for (let i = 16; i < 64; i++) {
      const s0 =
        rightRotate(W[i - 15], 7) ^
        rightRotate(W[i - 15], 18) ^
        (W[i - 15] >>> 3);
      const s1 =
        rightRotate(W[i - 2], 17) ^
        rightRotate(W[i - 2], 19) ^
        (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    return W;
  };

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // Main compute function with step-by-step live preview
  const computeHash = async () => {
    // Reset states
    setOriginalBinary("");
    setPaddedMessage("");
    setMessageSchedules([]);
    setCompressSteps([]);
    setUpdatedHashes([]);
    setFinalHash("");

    // Step 1: Binary conversion
    const binary = toBinary(input);
    setOriginalBinary(binary);
    await delay(1000);

    // Step 2: Message padding (preprocessing)
    const padded = preprocessMessage(input);
    setPaddedMessage(padded);
    await delay(1000);

    let hash = [...initialHash];
    let schedulesAcc = [];
    let compressAcc = [];
    let updatedHashesAcc = [];

    // Process each 512-bit block
    const blockCount = padded.length / 512;
    for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
      const block = padded.slice(blockIndex * 512, (blockIndex + 1) * 512);

      // Step 3: Message Schedule creation
      const schedule = createMessageSchedule(block);
      const scheduleHex = schedule.map((word) =>
        word.toString(16).padStart(8, "0")
      );
      schedulesAcc.push({ blockIndex: blockIndex + 1, schedule: scheduleHex });
      setMessageSchedules([...schedulesAcc]);
      await delay(1000);

      // Step 4: Compression function for this block
      let [a, b, c, d, e, f, g, h] = hash;
      const steps = [];
      for (let round = 0; round < 64; round++) {
        const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + K[round] + schedule[round]) >>> 0;
        const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;

        // Store detailed information for this round
        steps.push({
          round: round + 1,
          a: a.toString(16).padStart(8, "0"),
          b: b.toString(16).padStart(8, "0"),
          c: c.toString(16).padStart(8, "0"),
          d: d.toString(16).padStart(8, "0"),
          e: e.toString(16).padStart(8, "0"),
          f: f.toString(16).padStart(8, "0"),
          g: g.toString(16).padStart(8, "0"),
          h: h.toString(16).padStart(8, "0"),
          S0: S0.toString(16).padStart(8, "0"),
          S1: S1.toString(16).padStart(8, "0"),
          ch: ch.toString(16).padStart(8, "0"),
          maj: maj.toString(16).padStart(8, "0"),
          temp1: temp1.toString(16).padStart(8, "0"),
          temp2: temp2.toString(16).padStart(8, "0"),
        });
        // Update compression steps live for this block
        compressAcc = [
          ...compressAcc.filter((entry) => entry.blockIndex !== blockIndex + 1),
          { blockIndex: blockIndex + 1, steps: [...steps] },
        ];
        setCompressSteps([...compressAcc]);
        await delay(50); // Delay between rounds for visualization
      }
      // Update hash registers after processing this block
      hash = hash.map((hVal, i) => (hVal + [a, b, c, d, e, f, g, h][i]) >>> 0);

      // Save the updated registers (H0 to H7) as hex strings for this block
      updatedHashesAcc.push({
        blockIndex: blockIndex + 1,
        registers: hash.map((h) => h.toString(16).padStart(8, "0")),
      });
      setUpdatedHashes([...updatedHashesAcc]);
    }
    // Final hash in hexadecimal (concatenated registers)
    const finalHashHex = hash
      .map((h) => h.toString(16).padStart(8, "0"))
      .join("");
    setFinalHash(finalHashHex);
  };

  // Simple styling for live preview
  const cardStyle = {
    border: "1px solid #ccc",
    borderRadius: "8px",
    padding: "1rem",
    marginBottom: "1rem",
  };

  const sectionTitleStyle = { fontWeight: "bold", marginBottom: "0.5rem" };
  const monospaceStyle = { fontFamily: "monospace", fontSize: "0.85rem" };

  return (
    <div style={{ maxWidth: "800px", margin: "2rem auto", padding: "1rem" }}>
      <h2>SHA‑256 Full Process Live Preview</h2>
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
        <input
          type="text"
          placeholder="Enter text to hash..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          style={{ flex: 1, padding: "0.5rem" }}
        />
        <button onClick={computeHash} style={{ padding: "0.5rem 1rem" }}>
          Compute Hash
        </button>
      </div>

      {/* Step 1: Binary Conversion */}
      {originalBinary && (
        <div style={cardStyle}>
          <div style={sectionTitleStyle}>1. Binary Conversion</div>
          <div
            style={{
              ...monospaceStyle,
              overflowX: "auto",
              whiteSpace: "pre-wrap",
            }}
          >
            {originalBinary}
          </div>
        </div>
      )}

      {/* Step 2: Padded Message */}
      {paddedMessage && (
        <div style={cardStyle}>
          <div style={sectionTitleStyle}>2. Padded Message</div>
          <div
            style={{
              ...monospaceStyle,
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              wordWrap: "break-word",
            }}
          >
            {paddedMessage}
          </div>
        </div>
      )}

      {/* Step 3: Message Schedule for each block */}
      {messageSchedules.map((block) => (
        <div key={block.blockIndex} style={cardStyle}>
          <div style={sectionTitleStyle}>
            3. Message Schedule for Block {block.blockIndex}
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {block.schedule.map((word, i) => (
              <div
                key={i}
                style={{
                  background: "#e0f0ff",
                  padding: "0.3rem",
                  borderRadius: "4px",
                  minWidth: "70px",
                  textAlign: "center",
                }}
              >
                {word}
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Step 4: Compression Steps for each block */}
      {compressSteps.map((block) => (
        <div key={block.blockIndex} style={cardStyle}>
          <div style={sectionTitleStyle}>
            4. Compression Steps for Block {block.blockIndex}
          </div>
          <div style={{ maxHeight: "300px", overflowY: "auto" }}>
            {block.steps.map((step, idx) => (
              <div
                key={idx}
                style={{
                  background: "#f0f0f0",
                  padding: "0.5rem",
                  marginBottom: "0.25rem",
                  borderRadius: "4px",
                }}
              >
                <strong>Round {step.round}:</strong> <br />
                A: {step.a} | B: {step.b} | C: {step.c} | D: {step.d} <br />
                E: {step.e} | F: {step.f} | G: {step.g} | H: {step.h} <br />
                <em>
                  S0: {step.S0} | S1: {step.S1} | ch: {step.ch} | maj:{" "}
                  {step.maj}
                  <br />
                  temp1: {step.temp1} | temp2: {step.temp2}
                </em>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Updated Hash Registers (H0 - H7) */}
      {updatedHashes.length > 0 && (
        <div style={cardStyle}>
          <div style={sectionTitleStyle}>Updated Hash Registers</div>
          <div style={{ maxHeight: "200px", overflowY: "auto" }}>
            {updatedHashes.map((item) => (
              <div
                key={item.blockIndex}
                style={{
                  background: "#fff3cd",
                  padding: "0.5rem",
                  marginBottom: "0.5rem",
                  borderRadius: "4px",
                }}
              >
                <strong>After Block {item.blockIndex}:</strong>
                <div
                  style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: "1rem",
                    marginTop: "0.5rem",
                  }}
                >
                  {item.registers.map((reg, index) => (
                    <div
                      key={index}
                      style={{
                        background: "#f8f9fa",
                        padding: "0.3rem",
                        borderRadius: "4px",
                        minWidth: "80px",
                        textAlign: "center",
                      }}
                    >
                      H{index}: {reg}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Final Hash */}
      {finalHash && (
        <div style={cardStyle}>
          <div style={sectionTitleStyle}>Final Hash</div>
          <div
            style={{
              ...monospaceStyle,
              background: "#d4edda",
              padding: "0.5rem",
              borderRadius: "4px",
            }}
          >
            {finalHash}
          </div>
        </div>
      )}
    </div>
  );
};

export default SHA256Visualizer;
