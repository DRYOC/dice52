.PHONY: all build install test clean demo venv

all: install

venv:
	python3 -m venv .venv

install: venv
	. .venv/bin/activate && pip install --upgrade pip -q
	. .venv/bin/activate && pip install -r requirements.txt
	. .venv/bin/activate && pip install -e .

build:
	. .venv/bin/activate && python -m build

test:
	. .venv/bin/activate && python -m pytest tests/ -v

demo:
	. .venv/bin/activate && python -m dice52.demo

clean:
	rm -rf build/ dist/ *.egg-info .venv
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

