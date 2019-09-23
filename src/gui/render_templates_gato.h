/*
 *  Copyright (C) 2002-2015  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
/*
 * The HQ2x high quality 2x graphics filter.
 * Original author Maxim Stepin (see http://www.hiend3d.com/hq2x.html).
 * Adapted for DOSBox from ScummVM and HiEnd3D code by Kronuz.
 */
#include <stdio.h>
#ifndef RENDER_TEMPLATES_GATO_TABLE_H
#define RENDER_TEMPLATES_GATO_TABLE_H

#define PIXEL00_0	line0[0] = C4;
#define PIXEL00_10	line0[0] = interp_w2(C4,C0,3U,1U);
#define PIXEL00_11	line0[0] = interp_w2(C4,C3,3U,1U);
#define PIXEL00_12	line0[0] = interp_w2(C4,C1,3U,1U);
#define PIXEL00_20	line0[0] = interp_w3(C4,C3,C1,2U,1U,1U);
#define PIXEL00_21	line0[0] = interp_w3(C4,C0,C1,2U,1U,1U);
#define PIXEL00_22	line0[0] = interp_w3(C4,C0,C3,2U,1U,1U);
#define PIXEL00_60	line0[0] = interp_w3(C4,C1,C3,5U,2U,1U);
#define PIXEL00_61	line0[0] = interp_w3(C4,C3,C1,5U,2U,1U);
#define PIXEL00_70	line0[0] = interp_w3(C4,C3,C1,6U,1U,1U);
#define PIXEL00_90	line0[0] = interp_w3(C4,C3,C1,2U,3U,3U);
#define PIXEL00_100	line0[0] = interp_w3(C4,C3,C1,14U,1U,1U);

#define PIXEL01_0	line0[1] = C4;
#define PIXEL01_10	line0[1] = interp_w2(C4,C2,3U,1U);
#define PIXEL01_11	line0[1] = interp_w2(C4,C1,3U,1U);
#define PIXEL01_12	line0[1] = interp_w2(C4,C5,3U,1U);
#define PIXEL01_20	line0[1] = interp_w3(C4,C1,C5,2U,1U,1U);
#define PIXEL01_21	line0[1] = interp_w3(C4,C2,C5,2U,1U,1U);
#define PIXEL01_22	line0[1] = interp_w3(C4,C2,C1,2U,1U,1U);
#define PIXEL01_60	line0[1] = interp_w3(C4,C5,C1,5U,2U,1U);
#define PIXEL01_61	line0[1] = interp_w3(C4,C1,C5,5U,2U,1U);
#define PIXEL01_70	line0[1] = interp_w3(C4,C1,C5,6U,1U,1U);
#define PIXEL01_90	line0[1] = interp_w3(C4,C1,C5,2U,3U,3U);
#define PIXEL01_100	line0[1] = interp_w3(C4,C1,C5,14U,1U,1U);

#define PIXEL10_0	line1[0] = C4;
#define PIXEL10_10	line1[0] = interp_w2(C4,C6,3U,1U);
#define PIXEL10_11	line1[0] = interp_w2(C4,C7,3U,1U);
#define PIXEL10_12	line1[0] = interp_w2(C4,C3,3U,1U);
#define PIXEL10_20	line1[0] = interp_w3(C4,C7,C3,2U,1U,1U);
#define PIXEL10_21	line1[0] = interp_w3(C4,C6,C3,2U,1U,1U);
#define PIXEL10_22	line1[0] = interp_w3(C4,C6,C7,2U,1U,1U);
#define PIXEL10_60	line1[0] = interp_w3(C4,C3,C7,5U,2U,1U);
#define PIXEL10_61	line1[0] = interp_w3(C4,C7,C3,5U,2U,1U);
#define PIXEL10_70	line1[0] = interp_w3(C4,C7,C3,6U,1U,1U);
#define PIXEL10_90	line1[0] = interp_w3(C4,C7,C3,2U,3U,3U);
#define PIXEL10_100	line1[0] = interp_w3(C4,C7,C3,14U,1U,1U);

#define PIXEL11_0	line1[1] = C4;
#define PIXEL11_10	line1[1] = interp_w2(C4,C8,3U,1U);
#define PIXEL11_11	line1[1] = interp_w2(C4,C5,3U,1U);
#define PIXEL11_12	line1[1] = interp_w2(C4,C7,3U,1U);
#define PIXEL11_20	line1[1] = interp_w3(C4,C5,C7,2U,1U,1U);
#define PIXEL11_21	line1[1] = interp_w3(C4,C8,C7,2U,1U,1U);
#define PIXEL11_22	line1[1] = interp_w3(C4,C8,C5,2U,1U,1U);
#define PIXEL11_60	line1[1] = interp_w3(C4,C7,C5,5U,2U,1U);
#define PIXEL11_61	line1[1] = interp_w3(C4,C5,C7,5U,2U,1U);
#define PIXEL11_70	line1[1] = interp_w3(C4,C5,C7,6U,1U,1U);
#define PIXEL11_90	line1[1] = interp_w3(C4,C5,C7,2U,3U,3U);
#define PIXEL11_100	line1[1] = interp_w3(C4,C5,C7,14U,1U,1U);

#endif
/*
#if SBPP == 32
#define RGBtoYUV(c) _RGBtoYUV[((c & 0xf80000) >> 8) | ((c & 0x00fc00) >> 5) | ((c & 0x0000f8) >> 3)]
#else
#define RGBtoYUV(c) _RGBtoYUV[c]
#endif
*/
inline void conc2d(Gato,SBPP)(PTYPE * line0, PTYPE * line1, const PTYPE * fc)
{
    if ((C4 & 0xffffff) == 0xff55ff) {
        printf("MAGCENT %p\n", &C4);
    }
    line0[0] = C4;
    line0[1] = C4;
    line1[0] = C4;
    line1[1] = C4;
}

