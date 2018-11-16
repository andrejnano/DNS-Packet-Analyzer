
class TestItem(object):

    def __init__(self):
        self.description = 'Sample description for the test'
        self.command = ''
        self.returncode = 0

class TestSet(list):

    def __init__(self):
        self.count = 0
        self.successful_count = 0

    def add(self, description, command, returncode):
        test = TestItem()
        # prepare test 
        test.description = str(description)
        test.command = command
        test.returncode = returncode
        # add the test to the set
        self.append(test)
        self.count += 1
    
    def success(self):
        self.successful_count += 1
    
    def __str__(self):        
        return str('\nTesting results: {}/{} OK ({:0.2f}%)\n'.format(
            self.successful_count,
            self.count,
            self.successful_count/self.count*100
        ))

    def __iter__(self):
        for i in range(0, self.count):
            yield self[i]
