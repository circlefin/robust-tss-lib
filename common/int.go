// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
//
//  Portions Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved

package common

import (
	"math/big"
)

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

func (mi *modInt) Mod(x *big.Int) *big.Int {
	i := new(big.Int)
	return i.Mod(x, mi.i())
}

func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Div(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, mi.i())
}

func (mi *modInt) ModInverse(g *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, mi.i())
}

func (mi *modInt) IsCongruent(a, b *big.Int) bool {
	amodi := new(big.Int).Mod(a, mi.i())
	bmodi := new(big.Int).Mod(b, mi.i())
	return amodi.Cmp(bmodi) == 0
}

func (mi *modInt) IsAdditiveInverse(a, b *big.Int) bool {
	sum := mi.Add(a, b)
	zero := big.NewInt(0)
	return mi.IsCongruent(sum, zero)
}

func (mi *modInt) IsMultInverse(a, b *big.Int) bool {
	prod := mi.Mul(a, b)
	one := big.NewInt(1)
	return mi.IsCongruent(prod, one)
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}
