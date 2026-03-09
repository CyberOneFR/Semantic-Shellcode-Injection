#include <stdio.h>

void	*fake_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	size_t	result;
	size_t	gadget1;
	size_t	gadget2;
	size_t	gadget3;
	size_t	gadget4;
	size_t	setup;

	setup = (size_t)fake_mmap;
	while (*(size_t *)setup != 0xC353525657096A5B)
		setup++;
	((void (*)(void *, size_t, int, int, int, off_t))setup)(addr, length, prot, flags, fd, offset);
	setup = (size_t)fake_mmap;
	while (*(size_t *)setup != 0xC35351415041515B)
		setup++;
	((void (*)(void *, size_t, int, int, int, off_t))setup)(addr, length, prot, flags, fd, offset);
	gadget1 = (size_t)fake_mmap;
	gadget2 = (size_t)fake_mmap;
	gadget3 = (size_t)fake_mmap;
	gadget4 = (size_t)fake_mmap;
	while (*(size_t *)gadget1 != 0xC353050F58D7FF5B)
		gadget1++;
	while (*(size_t *)gadget2 != 0xC3505F5E5AD6FF58)
		gadget2++;
	while (*(size_t *)gadget3 != 0xC3575A41D2FF5F)
		gadget3++;
	while (*(size_t *)gadget4 != 0xC356584159415E)
		gadget4++;
	result = ((size_t (*)(size_t, size_t, size_t))gadget1)(gadget2, gadget3, gadget4);
	return ((void *)result);
}

long	fake_write(int fd, const void *buf, size_t count)
{
	size_t	result;

	result = (size_t)fake_write;
	while (*(size_t *)result != 0xC3050F58016A)
		result++;
	result = ((size_t (*)(int, const void *, size_t))result)(fd, buf, count);
	return (result);
}

int	main(void)
{
	char	*str = "Hello, World!\n";
	char	*ptr;

	ptr = fake_mmap(NULL, 0x1000, 0x7, 0x22, -1, 0);
	for (int i = 0; i < 14; i++)
		ptr[i] = str[i];
	fake_write(1, ptr, 14);
	return (0);
}