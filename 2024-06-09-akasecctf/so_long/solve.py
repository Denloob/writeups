#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import io as io_stream
from PIL import Image, ImageDraw
import base64
import numpy as np
import pyastar2d

host = args.HOST or "20.80.240.190"
port = int(args.PORT or 4442)

def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    return io

def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        raise NotImplementedError
    else:
        return start_remote(argv, *a, **kw)

io = start()

def base64_to_pil(base64_img: str | bytes) -> Image.Image:
    img_data = base64.b64decode(base64_img)
    pil_img = Image.open(io_stream.BytesIO(img_data))
    return pil_img

def recv_img() -> Image.Image:
    io.recvuntil(b"Round")
    io.recvline()
    b64 = io.recvline().strip()
    img = base64_to_pil(b64)
    return img
DIV = 4

def get_pixel_size(img):
    size = 1
    while img.getpixel((size, size)) != (255, 255, 255):
        size += 1
    print(f"{size=}")
    print(f"{img.getpixel((size, size))=}")
    return size

def parse_image(img: Image.Image):
    global DIV
    img = img.convert('RGB')
    width, height = img.size
    DIV = get_pixel_size(img)
    log.info(f"{width%3=}\t{height%3=}")
    log.info(f"{width%4=}\t{height%4=}")
    log.info(f"{width%5=}\t{height%5=}")
    log.info(f"{width%6=}\t{height%6=}")
    print(f"{DIV=}")
    grid_width, grid_height = width // DIV, height // DIV
    start, end = None, None
    grid = np.zeros((grid_height, grid_width), dtype=np.float32)
    for y in range(grid_height):
        for x in range(grid_width):
            pixel = img.getpixel((x*DIV, y*DIV))
            if pixel == (0, 255, 0):  
                start = (y, x)
                grid[y, x] = 1  
            elif pixel == (255, 0, 0):  
                end = (y, x)
                grid[y, x] = 1  
            elif pixel == (255, 255, 255):  
                grid[y, x] = 1  
            elif pixel == (0, 0, 0):  
                grid[y, x] = np.inf  
    return start, end, grid

def draw_path_on_image(img: Image.Image, path):
    draw = ImageDraw.Draw(img)
    for point in path:
        draw.point((point[1]*DIV, point[0]*DIV), fill=(0, 0, 255))  
    return img

def path_to_directions(path):
    direction_map = {
        (0, 1): "right",
        (1, 0): "down",
        (0, -1): "left",
        (-1, 0): "up",
        (1, 1): "down-right",
        (-1, 1): "up-right",
        (1, -1): "down-left",
        (-1, -1): "up-left"
    }
    directions = []
    for i in range(1, len(path)):
        move = (path[i][0] - path[i-1][0], path[i][1] - path[i-1][1])
        directions.append(direction_map[move])
    return " ".join(directions)

def print_np_array_to_file(array, file_path):
    np.savetxt(file_path, array, fmt='%s')
imt: Image.Image
import typing
path: typing.Any
i = 1
while True:
    try:
        img = recv_img()
    except Exception as e:
        draw_path_on_image(img, path)
        img.show()
        log.info(f"Error on img {i}")
        log.error(e)
    i += 1
    start, end, grid = parse_image(img)
    print_np_array_to_file(grid, "mygrid")
    path = pyastar2d.astar_path(grid, start, end, allow_diagonal=True)
    if path.shape[0] > 0:
        directions = path_to_directions(path)
        io.sendline(directions.encode())
    else:
        log.critical("No path found")
