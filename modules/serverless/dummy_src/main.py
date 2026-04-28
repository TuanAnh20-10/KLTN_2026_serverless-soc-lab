import functions_framework

@functions_framework.cloud_event
def main(cloud_event):
    print('Dummy SOC Bot running')
