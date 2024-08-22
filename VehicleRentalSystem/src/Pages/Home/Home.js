import HeroSection from '../../components/HomeComponents/HeroSection';
import GetStarted from '../../components/HomeComponents/GetStarted';
import Hiring from '../../components/HomeComponents/Hiring';
import { useContext } from 'react';
import { AuthContext } from '../../context/authContext'
import Explore from '../Explore/Explore';

export default function Home() {

    const { userDetails, isAuthenticated } = useContext(AuthContext);
 
    return (
        <div className="bg-white">

            {
                isAuthenticated ?
                    <Explore />
                    :
                    <>
                        <HeroSection />
                        <GetStarted />
                        <Hiring />
                    </>
            }

        </div>
    )
}
