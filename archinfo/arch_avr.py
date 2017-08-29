from .arch import Arch, register_arch, Endness

class ArchAVR(Arch):
    def __init__(self, endness=Endness.LE):
        super(ArchAVR, self).__init__(endness)

        self.bits = 16
        self.vex_arch = None
        self.name = "AVR"

        # Things I did not want to include but were necessary unfortunately :-(
        # self.cs_mode = capstone.CS_MODE_LITTLE_ENDIAN if endness == Endness.LE else capstone.CS_MODE_BIG_ENDIAN
        # END

        self.registers = {}
        self.registers.update({"r%d" % i            : (i, 1) for i in range(0, 32)})
        self.registers.update({"R%d_R%d" % (i+1, i) : (i, 2) for i in range(0, 32, 2)})

        self.registers["W"] =       (24, 2)
        self.registers["X"] =       (26, 2)
        self.registers["Y"] =       (28, 2)
        self.registers["Z"] =       (30, 2)

        self.registers["WL"] =      (24, 1)
        self.registers["WH"] =      (25, 1)
        self.registers["XL"] =      (26, 1)
        self.registers["XH"] =      (27, 1)
        self.registers["YL"] =      (28, 1)
        self.registers["YH"] =      (29, 1)
        self.registers["ZL"] =      (30, 1)
        self.registers["ZH"] =      (31, 1)

        self.registers["EEDR"] =    (0x40, 1)
        self.registers["EEARL"] =   (0x41, 1)
        self.registers["EEARH"] =   (0x42, 1)
        self.registers["GTCCR"] =   (0x43, 1)
        self.registers["TCCR0A"] =  (0x44, 1)
        self.registers["TCCR0B"] =  (0x45, 1)
        self.registers["TCNT0"] =   (0x46, 1)
        self.registers["OCR0A"] =   (0x47, 1)
        self.registers["OCR0B"] =   (0x48, 1)
        self.registers["IO_0x29"] = (0x49, 1)
        self.registers["GPIOR1"] =  (0x4a, 1)
        self.registers["GPIOR2"] =  (0x4b, 1)
        self.registers["SPCR"] =    (0x4c, 1)
        self.registers["SPSR"] =    (0x4d, 1)
        self.registers["SPDR"] =    (0x4e, 1)
        self.registers["IO_0x2f"] = (0x4f, 1)
        self.registers["ACSR"] =    (0x50, 1)
        self.registers["IO_0x31"] = (0x51, 1)
        self.registers["IO_0x32"] = (0x52, 1)
        self.registers["SMCR"] =    (0x53, 1)
        self.registers["MCUSR"] =   (0x54, 1)
        self.registers["MCUCR"] =   (0x55, 1)
        self.registers["IO_0x36"] = (0x56, 1)
        self.registers["SPMCSR"] =  (0x57, 1)
        self.registers["RAMPD"] =   (0x58, 1)
        self.registers["RAMPX"] =   (0x59, 1)
        self.registers["RAMPY"] =   (0x5a, 1)
        self.registers["RAMPZ"] =   (0x5b, 1)
        self.registers["EIND"] =    (0x5c, 1)

        self.registers["SP"] =      (0x5d, 2)
        self.registers["SPL"] =     (0x5d, 1)
        self.registers["SPH"] =     (0x5e, 1)

        self.registers["SREG"] =    (0x5f, 1)

        self.registers["WDTCSR"] =  (0x60, 1)
        self.registers["CLKPR"] =   (0x61, 1)
        self.registers["PRR"] =     (0x64, 1)
        self.registers["OSCCAL"] =  (0x66, 1)
        self.registers["PCICR"] =   (0x68, 1)
        self.registers["EICRA"] =   (0x69, 1)
        self.registers["PCMSK0"] =  (0x6b, 1)
        self.registers["PCMSK2"] =  (0x6d, 1)
        self.registers["PCMSK1"] =  (0x6c, 1)
        self.registers["TIMSK0"] =  (0x6e, 1)
        self.registers["TIMSK1"] =  (0x6f, 1)
        self.registers["TIMSK2"] =  (0x70, 1)
        self.registers["ADCL"] =    (0x78, 1)
        self.registers["ADCH"] =    (0x79, 1)
        self.registers["ADCSRA"] =  (0x7a, 1)
        self.registers["ADCSRB"] =  (0x7b, 1)
        self.registers["ADMUX"] =   (0x7c, 1)
        self.registers["DIDR0"] =   (0x7e, 1)
        self.registers["DIDR1"] =   (0x7f, 1)
        self.registers["TCCR1A"] =  (0x80, 1)
        self.registers["TCCR1B"] =  (0x81, 1)
        self.registers["TCCR1C"] =  (0x82, 1)
        self.registers["TCNT1H"] =  (0x85, 1)
        self.registers["TCNT1L"] =  (0x84, 1)
        self.registers["ICR1H"] =   (0x87, 1)
        self.registers["ICR1L"] =   (0x86, 1)
        self.registers["OCR1AH"] =  (0x89, 1)
        self.registers["OCR1AL"] =  (0x88, 1)
        self.registers["OCR1BH"] =  (0x8b, 1)
        self.registers["OCR1BL"] =  (0x8a, 1)
        self.registers["TCCR2A"] =  (0xb0, 1)
        self.registers["TCCR2B"] =  (0xb1, 1)
        self.registers["TCNT2"] =   (0xb2, 1)
        self.registers["OCR2A"] =   (0xb3, 1)
        self.registers["OCR2B"] =   (0xb4, 1)
        self.registers["ASSR"] =    (0xb6, 1)
        self.registers["TWBR"] =    (0xb8, 1)
        self.registers["TWSR"] =    (0xb9, 1)
        self.registers["TWAR"] =    (0xba, 1)
        self.registers["TWDR"] =    (0xbb, 1)
        self.registers["TWCR"] =    (0xbc, 1)
        self.registers["TWAMR"] =   (0xbd, 1)
        self.registers["UCSR0A"] =  (0xc0, 1)
        self.registers["UCSR0B"] =  (0xc1, 1)
        self.registers["UCSR0C"] =  (0xc2, 1)
        self.registers["UBRR0H"] =  (0xc5, 1)
        self.registers["UBRR0L"] =  (0xc4, 1)
        self.registers["UDR0"] =    (0xc6, 1)

        self.registers["pc"] =      (0x80000000, 2)
        self.registers["ip"] =      (0x80000000, 2)

        self.register_names = {}
        self.register_names.update({i: "r%d" % i for i in range(0, 32)})
        self.register_names[self.registers['pc'][0]] = 'pc'

        self.ip_offset = self.registers["pc"][0]

register_arch(['avr.*|atiny.*|atmega.*|atmel.*'], 8, Endness.LE, ArchAVR)
