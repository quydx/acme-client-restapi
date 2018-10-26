# Build docker image base

```
docker build -t vcertbot .
```

# Run container

```
docker run -v -e "DOMAIN=quydx11.tk"  vcertbot
```

# cache yum when start container by build docker image from container

```
docker commit <container_id> <new_image_name>
```

