MEMORY
/* Custom memory.x file for tests */
/*
    Tests don't use the pro- and epilogue because making them support
   running from RAM takes unnecessary effort
*/

{
  /* This file is intended for parts in the STM32H723 family. (RM0468)      */
  /* - FLASH and RAM are mandatory memory sections.                         */
  /* - The sum of all non-FLASH sections must add to 564k total device RAM. */
  /* - The FLASH section size must match your device, see table below.      */

  /* FLASH */
  /* Select the appropriate FLASH size for your device. */
  /* - STM32H730xB                                 128K */
  /* - STM32H723xE/725xE                           512K */
  /* - STM32H723xG/725xG/733xG/735xG                 1M */
  FLASH1  : ORIGIN = 0x08000000, LENGTH = 1M

  /* Data TCM  */
  /* - Two contiguous 64KB RAMs.                                     */
  /* - Used for interrupt handlers, stacks and general RAM.          */
  /* - Zero wait-states.                                             */
  /* - The DTCM is taken as the origin of the base ram. (See below.) */
  /*   This is also where the interrupt table and such will live,    */
  /*   which is required for deterministic performance.              */
  DTCM    : ORIGIN = 0x20000000, LENGTH = 128K

  /* Instruction TCM */
  /* - More memory can be assigned to ITCM. See AXI SRAM notes, below. */
  /* - Used for latency-critical interrupt handlers etc.               */
  /* - Zero wait-states.                                               */
  ITCM    : ORIGIN = 0x00000000, LENGTH = 64K + 0K

  /* AXI SRAM */
  /* - AXISRAM is in D1 and accessible by all system masters except BDMA.         */
  /* - Suitable for application data not stored in DTCM.                          */
  /* - Zero wait-states.                                                          */
  /* - The 192k of extra shared RAM is fully allotted to the AXI SRAM by default. */
  /*   As a result: 64k (64k + 0k) for ITCM and 320k (128k + 192k) for AXI SRAM.  */
  /*   This can be re-configured via the TCM_AXI_SHARED[1,0] register when more   */
  /*   ITCM is required.                                                          */
  AXISRAM : ORIGIN = 0x24000000, LENGTH = 128K + 192K

  /* AHB SRAM */
  /* - SRAM1-2 are in D2 and accessible by all system masters except BDMA, LTDC */
  /*   and SDMMC1. Suitable for use as DMA buffers.                             */
  /* - SRAM4 is in D3 and additionally accessible by the BDMA. Used for BDMA    */
  /*   buffers, for storing application data in lower-power modes.              */
  /* - Zero wait-states.                                                        */
  SRAM1   : ORIGIN = 0x30000000, LENGTH = 16K
  SRAM2   : ORIGIN = 0x30040000, LENGTH = 16K
  SRAM4   : ORIGIN = 0x38000000, LENGTH = 16K

  /* Backup SRAM */
  /* Used to store data during low-power sleeps. */
  BSRAM   : ORIGIN = 0x38800000, LENGTH = 4K
}

/*
/* Assign the memory regions defined above for use. */
/*

/* Provide the mandatory FLASH and RAM definitions for cortex-m-rt's linker script. */
REGION_ALIAS(FLASH, AXISRAM);
REGION_ALIAS(RAM,   DTCM);
