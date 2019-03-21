global.btoa = str => Buffer.from(str).toString("base64");
global.atob = str => Buffer.from(str, "base64").toString();
