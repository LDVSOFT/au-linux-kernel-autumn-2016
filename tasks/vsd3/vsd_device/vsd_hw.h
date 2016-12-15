#ifndef _VSD_HW_H
#define _VSD_HW_H

#define VSD_CMD_NONE 0
#define VSD_CMD_WRITE 1
#define VSD_CMD_READ 2
#define VSD_CMD_SET_SIZE 3

typedef struct vsd_hw_regs {
    // Command to run
    uint8_t cmd;
    // Result of command execution.
    // Same as Linux kernel error codes.
    int32_t result;
    // The only not "real" thing here
    // We use "software interrupt" instead of hardware
    // VSD will call this tasklet when cmd is completed
    uint64_t tasklet_vaddr;
    // DMA buffer physiscal address
    uint64_t dma_paddr;
    // DMA buffer size
    uint64_t dma_size;
    // Destination buffer offset inside device
    // or new device size in case of VSD_CMD_SET_SIZE
    uint64_t dev_offset;

    // Read only data
    uint64_t dev_size;
} vsd_hw_regs_t;

#endif // _VSD_HW_H
