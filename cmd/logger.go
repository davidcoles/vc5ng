/*
 * VC5 load balancer. Copyright (C) 2021-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package main

import (
	"log"
)

const (
	EMERG   = 0
	ALERT   = 1
	CRIT    = 2
	ERR     = 3
	WARNING = 4
	NOTICE  = 5
	INFO    = 6
	DEBUG   = 7
)

type logger struct {
}

func (l logger) Println(a ...any) {
	log.Println(append([]any{"LOGGER"}, a...)...)
}

func level(l uint8) string {
	a := []string{"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"}

	if int(l) < len(a) {
		return a[l]
	}

	return "XXX"
}

func (l logger) log(n uint8, s string, a ...any) { l.Println(append([]any{level(n), s}, a...)...) }

func (l logger) EMERG(s string, a ...any)   { l.log(EMERG, s, a...) }
func (l logger) ALERT(s string, a ...any)   { l.log(ALERT, s, a...) }
func (l logger) CRIT(s string, a ...any)    { l.log(CRIT, s, a...) }
func (l logger) ERR(s string, a ...any)     { l.log(ERR, s, a...) }
func (l logger) WARNING(s string, a ...any) { l.log(WARNING, s, a...) }
func (l logger) NOTICE(s string, a ...any)  { l.log(NOTICE, s, a...) }
func (l logger) INFO(s string, a ...any)    { l.log(INFO, s, a...) }
func (l logger) DEBUG(s string, a ...any)   { l.log(DEBUG, s, a...) }
