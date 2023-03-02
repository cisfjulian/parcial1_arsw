package edu.eci.arsw.threads;

import edu.eci.arsw.blacklistvalidator.HostBlackListsValidator;
import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;

public class Busqueda extends Thread{

    private int fin,inicio;

    public void setInicioFin(int inicio, int fin){
        this.inicio = inicio;
        this.fin = fin;
    }

    @Override
    public void run() {
        super.run();
        HostBlackListsValidator hblv=new HostBlackListsValidator();
        List<Integer> blackListOcurrences=hblv.checkHost("200.24.34.55", 4);
        System.out.println("The host was found in the following blacklists:"+blackListOcurrences);
    }
}
