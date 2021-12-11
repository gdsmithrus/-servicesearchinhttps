# Read csv File
def readFileCSVFormat(filePath, hasHeader=True):
    with open(filePath) as f:
        if hasHeader: f.readline()
        data = []
        for line in f:
            line = line.strip().split(",")
            if line[0] != "Tnum":
                data.append([x for x in line])
    return data
