FROM itsafeaturemythic/mythic_python_base:latest
RUN apt-get update && apt-get install -y build-essential mingw-w64
# donut : PE → shellcode position-independent (TheWover/donut)
RUN pip3 install donut-shellcode
WORKDIR /Mythic/
CMD ["python3", "main.py"]
