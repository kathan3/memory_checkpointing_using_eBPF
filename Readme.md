# Saving Process Context using ebpf

Make sure you are in the root user or can do sudo.

first you can run .teardown.sh which will delete all the files in /tmp if it exist.

```bash
./teardown.sh
```
Now first start exec binary in root privillages and then start the testcase.

```bash
sudo ./exec
```
