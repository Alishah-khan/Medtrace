# MedTrace: offline-first verifiable custody box

Folders
- `firmware/medtrace/`  ESP32 sketch (open `medtrace.ino` in Arduino IDE)
- `backend/`            FastAPI server (verification, Merkle roots, risk score) + demo tools
- `chain/`              Solidity contract + deploy script
- `frontend/`           dashboard and verify page (served by the backend)
- `firmware/host_test/` PC simulator output used by `backend/tools/test_with_sim.py`

## 1. Start the blockchain (window 1, keep it open)
    cd chain
    npm install
    npx hardhat node

## 2. Deploy the contract (window 2)
    cd chain
    node deploy.js

## 3. Start the backend (window 3)
    cd backend
    python -m venv venv
    venv\Scripts\activate          (Linux/Mac: source venv/bin/activate)
    pip install -r requirements.txt
    uvicorn app:app --host 0.0.0.0 --port 8000
Open http://localhost:8000 . Allow port 8000 in the Windows firewall so the ESP32 can reach it.

## 4. Test everything without hardware (needs a FRESH chain: restart step 1, redo step 2)
    cd backend
    python tools/test_with_sim.py

## 5. Real box
1. Edit `firmware/medtrace/config.h` (WiFi, laptop IP, card UIDs), upload, open Serial Monitor at 115200.
2. Copy the public key block printed at boot into `backend/pubkey.pem`.
3. `python tools/register_box.py BOX-001 pubkey.pem`
4. `python tools/register_handler.py 04A1B2C3 04D4E5F6 04112233`   (your real card UIDs)
5. Dashboard: http://<laptop-ip>:8000/?box=BOX-001&verify=1  (make a QR code of this link)

## Demo attacks
    python tools/tamper_demo.py BOX-001 edit      then refresh the verify page -> TAMPERED
    python tools/tamper_demo.py BOX-001 restore   -> VERIFIED again
    python tools/fake_sender.py BOX-001           -> rejected (invalid signature)

## Full reset (clean demo)
Stop everything, delete `backend/medtrace.db`, restart `npx hardhat node`, run `node deploy.js`,
register the box and cards again, then type `ERASE YES` in the ESP32 Serial Monitor.
