# LLM-enabled Youtube Focus Filter

First, use this link https://gist.githubusercontent.com/chihumyum/d3a66649d59bde00e7587721424e438d/raw/549d1450bf19c058d0eb23de29dcef50b29cdc48/gistfile1.txt to get pac file for your system. 

For instructions of how to config pac file, see [macOS](https://support.apple.com/zh-sg/guide/mac-help/mchlp2591/mac) or [windows](https://medium.com/@gireeshagmt/tackling-proxy-how-to-use-proxy-auto-config-pac-on-windows-11-e9a6fa585918).


Then, start the container:
```
chmod +x up.sh
./up.sh
```

And the proxy should be up and running.

Visit localhost:5001 to access the web UI, where you can edit your focus goals.

Finally, visit Youtube, and enjoy your focused browsing experience!
