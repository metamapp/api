.DEFAULT_GOAL := help

.PHONY: proto

help:
	@grep -E '^[a-zA-Z/_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

raw/raw.pb.go: raw/raw.proto
	@echo ">> Generating raw/raw.pb.go"
	@protoc --proto_path=raw --go_out=raw \
	    --go_opt=paths=source_relative raw/raw.proto

proto: raw/raw.pb.go ## generate protobuf bindings

proto/clean: ## remove generated protobuf bindings
	@rm raw/raw.pb.go
