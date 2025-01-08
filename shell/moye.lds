ENTRY(_reset)

MEMORY {
  TEXT (rx) : ORIGIN = (0x9000000), LENGTH = 0x20000
}

_text_virt_begin = ORIGIN(TEXT);
_text_virt_end = LENGTH(TEXT) + ORIGIN(TEXT);


SECTIONS {
  .text : {
    _text_begin = .;
    * (.text)
    * (.text.*)
    . = ALIGN(0x1000);
    _text_end = .;
  }
}
