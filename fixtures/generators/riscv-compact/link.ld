
ENTRY(_start)
SECTIONS
{
    .iram 0x40380000 : {
        *(.text*)
    }
}
