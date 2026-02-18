KERNEL_VERSION = "6.6.13"
INCLUDE_FOLDER = "internal/bpf/siit/include"
generate: go-generate

go-generate:
	docker build -t siit-ebpf-deps --target deps .
	docker run -ti -v $(PWD):/work -w /work siit-ebpf-deps go generate ./...



ebpf-test:
	docker run --privileged -v $(shell go env GOMODCACHE):/go/pkg/mod -v $(PWD):/src -v /sys/kernel/tracing:/sys/kernel/tracing:rw -w /src golang go test -v ./internal/bpf/...

generate-btf-headers:
	docker build -t bpftool https://github.com/libbpf/bpftool.git#main
	docker run bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(INCLUDE_FOLDER)/vmlinux.h

generate-libbpf-headers:
	docker build -f Dockerfile.libbpf -t libbpf .
	docker create --name libbpf libbpf
	docker cp libbpf:/usr/include/bpf $(INCLUDE_FOLDER)
	docker rm -f libbpf
	find $(INCLUDE_FOLDER)/bpf -maxdepth 1 -type f ! -name "bpf*.h" -delete

generate-linux-headers:
	crane pull -c /tmp/linuxkit linuxkit/kernel:$(KERNEL_VERSION) linuxkit.tar
	mkdir linuxkit || true
	tar -xf  "linuxkit.tar" -C linuxkit
	rm linuxkit.tar
	tar -xzvf `find linuxkit -name "*.tar.gz"` -C linuxkit
	mkdir /tmp/linux || true
	tar -xf "linuxkit/kernel-headers.tar" -C /tmp/linux
	cp -R /tmp/linux/usr/include/linux/ $(INCLUDE_FOLDER)/linux-headers
	# cp -R /tmp/linux/usr/include/asm-generic $(INCLUDE_FOLDER)
	rm -r linuxkit
