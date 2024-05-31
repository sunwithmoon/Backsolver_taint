# Angr Taint IIFV
This repository contains the necessary modules to identify IIFV information of a binary.
It is based on [https://github.com/badnack/angr_taint_engine](https://github.com/badnack/angr_taint_engine)

# Example
```shell
python ifv_finder/ifv_finder.py binary_path --ifv_path ./pickle_data/binary.pk
```
The results are saved in the `./pickle_data` directory.
`binary.pk` are the recognized IFVs, while `binary_fin.pk` saves the IIFV information. 
You can use `binary_fin.pk` for [Backsolver](https://github.com/sunwithmoon/Backsolver).