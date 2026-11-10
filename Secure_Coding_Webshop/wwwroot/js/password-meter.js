/* Adgangskodemåler og forslag til adgangskode.
   VIGTIGT: Det her er kun hjælp til brugeren. Reglerne håndhæves på serveren (PasswordPolicy + HIBP + Argon2id).
   Ingen inline script (CSP): filen indlæses med <script src>. Ingenting sendes noget sted hen. */
(function () {
  "use strict";

  var COMMON = ["password", "passw0rd", "adgangskode", "qwerty", "qwertyuiop", "letmein", "welcome", "admin",
    "iloveyou", "monkey", "dragon", "football", "baseball", "sommer", "vinter", "danmark", "kaerlighed", "123456"];

  function charPool(p) {
    var pool = 0;
    if (/[a-zæøå]/.test(p)) pool += 29;
    if (/[A-ZÆØÅ]/.test(p)) pool += 29;
    if (/[0-9]/.test(p)) pool += 10;
    if (/[^A-Za-z0-9æøåÆØÅ]/.test(p)) pool += 33;
    return pool || 1;
  }

  function hasSequence(p) {
    var l = p.toLowerCase(), runs = 0;
    for (var i = 0; i < l.length - 2; i++) {
      var a = l.charCodeAt(i), b = l.charCodeAt(i + 1), c = l.charCodeAt(i + 2);
      if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) runs++;
    }
    return runs > 0;
  }
  function hasRepeat(p) { return /(.)\1{2,}/.test(p) || /^(.{1,4})\1+$/.test(p); }
  function hasKeyboardWalk(p) {
    var rows = ["qwertyuiopå", "asdfghjklæø", "zxcvbnm", "1234567890"], l = p.toLowerCase();
    for (var r = 0; r < rows.length; r++)
      for (var i = 0; i + 4 <= rows[r].length; i++) {
        var seg = rows[r].substr(i, 4);
        if (l.indexOf(seg) !== -1 || l.indexOf(seg.split("").reverse().join("")) !== -1) return true;
      }
    return false;
  }

  /* Groft estimat af bits entropi, med fradrag for kendte mønstre */
  function estimateBits(p) {
    if (!p) return 0;
    var bits = p.length * Math.log2(charPool(p));
    var lower = p.toLowerCase();
    for (var i = 0; i < COMMON.length; i++) if (lower.indexOf(COMMON[i]) !== -1) bits -= 20;
    if (hasSequence(p)) bits -= 10;
    if (hasRepeat(p)) bits -= 15;
    if (hasKeyboardWalk(p)) bits -= 15;
    // Ord adskilt af mellemrum (en passphrase) er stærkere end tegnpuljen antyder, men ikke så meget som tilfældige tegn
    return Math.max(0, bits);
  }

  function describe(bits) {
    if (bits < 40) return { text: "Svag", cls: "weak" };
    if (bits < 60) return { text: "Middel", cls: "fair" };
    if (bits < 80) return { text: "Stærk", cls: "strong" };
    return { text: "Meget stærk", cls: "excellent" };
  }

  /* Ordliste til passphrases (192 almindelige danske ord uden lighed med hinanden). 7 ord = ca. 53 bit */
  var WORDS = ("hav,skov,mark,bro,hus,vej,dør,vindue,stol,bord,lampe,seng,kniv,gaffel,kop,glas,tallerken,spand,nøgle,lås," +
    "bil,cykel,tog,båd,fly,hest,ko,gris,får,høne,ræv,ulv,bjørn,fugl,fisk,krabbe,sne,regn,sol,måne,stjerne,vind,sky,tåge,torden,is," +
    "æble,pære,kirsebær,banan,gulerod,kartoffel,løg,brød,smør,ost,mælk,æg,suppe,kage,kaffe,te,vand,salt,peber,sukker," +
    "rød,blå,grøn,gul,sort,hvid,lilla,orange,brun,grå,stor,lille,hurtig,langsom,stærk,blød,hård,varm,kold,tung," +
    "bog,pen,papir,sax,lim,kort,ur,bold,spil,musik,sang,tromme,guitar,klaver,maler,dans,film,bad,have,blomst," +
    "træ,blad,rod,græs,sten,sand,bjerg,dal,sø,å,ø,kyst,strand,bølge,havn,fyr,mølle,slot,tårn,port," +
    "mand,kvinde,barn,ven,nabo,lærer,læge,bager,smed,fisker,bonde,kok,pilot,maler,kaptajn,konge,dronning,prins,ridder,drage," +
    "morgen,aften,nat,dag,uge,måned,år,time,minut,vinter,forår,sommer,efterår,fest,rejse,eventyr,drøm,hemmelighed,vidunder,minde," +
    "kompas,anker,sejl,lanterne,telt,bål,tæppe,hue,sko,jakke,handske,halstørklæde,paraply,rygsæk,flaske,pose,kasse,tønde,kurv,stige").split(",");

  function randomInt(max) {
    var buf = new Uint32Array(1), limit = Math.floor(4294967296 / max) * max, v;
    do { crypto.getRandomValues(buf); v = buf[0]; } while (v >= limit);   // ingen modulo-bias
    return v % max;
  }
  function passphrase(count) {
    var out = [];
    for (var i = 0; i < count; i++) out.push(WORDS[randomInt(WORDS.length)]);
    return out.join("-");
  }

  var input = document.getElementById("new-password");
  var meter = document.getElementById("password-meter");
  if (input && meter) {
    input.addEventListener("input", function () {
      var bits = estimateBits(input.value), d = describe(bits);
      meter.textContent = input.value ? d.text + " (ca. " + Math.round(bits) + " bit)" : "";
      meter.className = d.cls;
    });
  }

  var button = document.getElementById("generate-passphrase");
  var output = document.getElementById("passphrase-output");
  if (button && output) {
    button.addEventListener("click", function () {
      var phrase = passphrase(7);
      output.textContent = phrase;
      if (input) { input.value = phrase; input.dispatchEvent(new Event("input")); }
    });
  }
})();
