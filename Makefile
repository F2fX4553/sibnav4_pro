.PHONY: all clean core cpp python

all: core cpp python

core:
	cd core && cargo build --release --features "ffi"

cpp: core
	mkdir -p bindings/cpp/build
	cd bindings/cpp/build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j

python: core
	cd bindings/python && pip install -e .

clean:
	cd core && cargo clean
	rm -rf bindings/cpp/build
	rm -rf bindings/python/build bindings/python/dist bindings/python/*.egg-info
