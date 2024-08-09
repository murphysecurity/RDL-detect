# Remote Desktop Licensing 服务排查 
参考https://github.com/fortra/impacket/blob/master/examples/rpcdump.py

通过MSRPC枚举开放服务，根据UUID: 3d267954-eeb7-11d1-b94e-00c04fa3080d判断是否包含Terminal Server Licensing 

用法：`python3 rdl-detect.py 目标IP`