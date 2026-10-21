install:
	python -m pip install -r requirements/dev.txt
run:
	python run.py
check:
	python -m compileall phishhunter libs tests
	ruff check phishhunter libs tests
	black --check phishhunter libs tests
	pytest
