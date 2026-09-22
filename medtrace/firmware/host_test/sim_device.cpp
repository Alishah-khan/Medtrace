// Host-side simulator: uses the SAME firmware code (mt_crypto.h, mt_record.h) on a PC.
// Writes: sim_pub.pem, sim_log.jsonl  ->  used by backend/tools/test_with_sim.py
#include <cstdio>
#include <fstream>
#include <iostream>

#include "../medtrace/mt_record.h"

int main() {
  mt::Signer signer;
  if (!signer.begin("")) { std::cerr << "key generation failed\n"; return 1; }

  // key reload test (same path the ESP32 uses after a reboot)
  std::string priv = signer.privatePem();
  mt::Signer signer2;
  if (priv.empty() || !signer2.begin(priv)) { std::cerr << "key reload failed\n"; return 1; }

  std::ofstream(std::string("sim_pub.pem")) << signer2.publicPem();

  mt::Chain chain;
  chain.box = "BOX-SIM";
  chain.signer = &signer2;

  struct Item { char kind; const char* data; uint32_t ts; };
  Item items[] = {
    {'E', "BOOT;0", 1790000000},
    {'R', "4.25;0;0", 1790000010},
    {'R', "4.30;0;0", 1790000020},
    {'H', "04A1B2C3;04D4E5F6;4.25;4.30;0;0", 1790000030},
    {'R', "4.40;0;0", 1790000040},
    {'E', "DOOR_OPEN;1", 1790000045},
    {'R', "9.10;1;0", 1790000050},
    {'E', "TEMP_OUT;9.10", 1790000050},
    {'R', "9.60;1;0", 1790000060},
    {'R', "9.80;1;0", 1790000070},
    {'E', "DOOR_CLOSE;0", 1790000075},
    {'R', "5.10;0;0", 1790000080},
    {'E', "UNAUTH_CARD;DEADBEEF", 1790000085},
  };
  std::ofstream log("sim_log.jsonl");
  for (auto& it : items) {
    mt::Rec r = chain.build(it.kind, it.data, it.ts);
    if (!r.ok) { std::cerr << "build failed\n"; return 1; }
    chain.commit(r);
    log << r.line << "\n";
  }
  std::cout << "wrote " << chain.seq << " records\n";
  return 0;
}
