/*
 * This file is part of the BSGS distribution
 * (https://github.com/JeanLucPons/Kangaroo). Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SECP256K1H
#define SECP256K1H

#include <string>
#include <vector>

#include "Point.h"

// Address type
const unsigned int P2PKH = 0;
const unsigned int P2SH = 1;
const unsigned int BECH32 = 2;

class Secp256K1 {
 public:
  Secp256K1();
  ~Secp256K1();
  void Init();
  Point ComputePublicKey(Int *privKey, bool reduce = true);
  std::vector<Point> ComputePublicKeys(std::vector<Int> &privKeys);
  std::string GetAddress(int type, bool compressed, Point &pubKey);
  Point NextKey(Point &key);
  bool EC(Point &p);

  std::string GetPublicKeyHex(bool compressed, Point &p);
  bool ParsePublicKeyHex(std::string str, Point &p, bool &isCompressed);

  Point Add(Point &p1, Point &p2);
  Point Add2(Point &p1, Point &p2);
  Point AddDirect(Point &p1, Point &p2);
  Point Double(Point &p);
  Point DoubleDirect(Point &p);

  std::vector<Point> AddDirect(std::vector<Point> &p1, std::vector<Point> &p2);

  Point G;    // Generator
  Int order;  // Curve order

 private:
  uint8_t GetByte(std::string &str, int idx);

  Int GetY(Int x, bool isEven);
  Point GTable[256 * 32];  // Generator table
  void GetHash160(int type, bool compressed, Point &pubKey,
                  unsigned char *hash);
};

#endif  // SECP256K1H
