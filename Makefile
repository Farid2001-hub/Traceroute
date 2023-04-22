venv/bin/activate: requirements.txt
	apt install python3.8-venv
	python3 -m venv venv
	apt install python3-pip
	apt install python3-tk
	./venv/bin/pip install -r requirements.txt

run: venv/bin/activate
	./venv/bin/python3 traceroute.py  

clean:
	rm -rf __pycache__
	rm -rf venv
