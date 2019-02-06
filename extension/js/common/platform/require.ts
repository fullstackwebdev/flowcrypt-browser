/* © 2016-2018 FlowCrypt Limited. Limitations apply. Contact human@flowcrypt.com */

"use strict";

//import Swal from 'sweetalert2';

/// <reference path="../../../types/openpgp.d.ts" />
/// <reference path="../../../types/sweetalert2.d.ts" />

declare const openpgp: typeof OpenPGP;

type Codec = {
  encode: (text: string, mode: "fatal" | "html") => string;
  decode: (text: string) => string;
  labels: string[];
  version: string;
};

export const requireOpenpgp = (): typeof OpenPGP => {
  try {
    return openpgp;
  } catch (e) {
    // a hack for the content scripts, which may not need openpgp, until I come up with something better
    return (undefined as any) as typeof OpenPGP;
  }
};

export const requireSweetAlert2 = (): any => {
  return (window as any)["Swal"];
};

export const requireMimeParser = (): any => {
  return (window as any)["emailjs-mime-parser"];
};

export const requireMimeBuilder = (): any => {
  return (window as any)["emailjs-mime-builder"];
};

export const requireIso88592 = (): Codec => {
  return (window as any).iso88592 as Codec;
};
