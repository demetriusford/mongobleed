.PHONY: lint lint-fix install run clean help

help:
	@echo "Available targets:"
	@echo "  make install   - Install dependencies"
	@echo "  make lint      - Run RuboCop"
	@echo "  make lint-fix  - Run RuboCop with auto-fix"
	@echo "  make run       - Run script (use ARGS for options)"
	@echo "  make clean     - Remove output files"

install:
	bundle install

lint:
	bundle exec rubocop

lint-fix:
	bundle exec rubocop -A

run:
	bundle exec ruby mongobleed.rb $(ARGS)

clean:
	rm -f *.bin leaked.bin
